use crate::{
    bundle,
    handoff::{select_handoff, Handoff, HostCapabilities},
    manifest::{
        Layout, RootPartitionIdentity, SelfInstallManifest, SelfInstallSource, StagingStrategy,
    },
    network::{NetworkConfig, NetworkMode},
    rootfs::{ArchiveFormat, RootfsDescriptor},
    safety, EncvolError,
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use url::Url;

const MIB: u64 = 1024 * 1024;
const DEFAULT_HTTPS_STAGING_MIB: u64 = 4096;
const LIVE_ROOT_HEADROOM_MIB: u64 = 1024;
const MIN_ROOT_HEADROOM_MIB: u64 = 2048;

#[derive(Debug, Serialize)]
pub struct SelfInstallPlan {
    pub target_disk: String,
    pub handoff: Handoff,
    pub root_partition: RootPartitionIdentity,
    pub source: String,
    pub staging: StagingStrategy,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SelfInstallRequest {
    pub disk: String,
    pub rootfs_descriptor: Option<Url>,
    pub use_live_root: bool,
    pub tang_url: Url,
    pub tang_thumbprint: String,
    pub recovery_authorized_key: String,
    pub swap_mib: u64,
    pub data_volume: bool,
}

#[derive(Debug, Clone)]
struct RootProbe {
    identity: RootPartitionIdentity,
    used_bytes: u64,
    partition_start_mib: u64,
    partition_size_mib: u64,
}

#[derive(Debug, Clone)]
struct FreeRegion {
    size_mib: u64,
}

fn command_stdout(program: &str, args: &[&str]) -> Result<String, EncvolError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| EncvolError::Unsupported(format!("cannot run {program}: {e}")))?;
    if !output.status.success() {
        return Err(EncvolError::Unsupported(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn program_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|p| p.join(name).is_file()))
}

fn mounted_esp() -> Option<PathBuf> {
    fs::read_to_string("/proc/mounts")
        .ok()?
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 3 && matches!(fields[2], "vfat" | "fat" | "msdos") {
                let path = PathBuf::from(fields[1]);
                path.is_dir().then_some(path)
            } else {
                None
            }
        })
}

fn self_install_handoff() -> (Handoff, HostCapabilities) {
    let uefi = Path::new("/sys/firmware/efi").is_dir();
    let capabilities = HostCapabilities {
        kexec: program_exists("kexec"),
        uefi,
        writable_esp: if uefi { mounted_esp() } else { None },
        efi_variables: Path::new("/sys/firmware/efi/efivars").is_dir(),
        grub: program_exists("grub-reboot") && Path::new("/boot/grub/grub.cfg").is_file(),
    };
    (select_handoff(&capabilities), capabilities)
}

fn disk_name(disk: &str) -> &str {
    Path::new(disk)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
}

fn root_probe(disk: &str) -> Result<RootProbe, EncvolError> {
    let source = command_stdout("findmnt", &["-n", "-o", "SOURCE", "--target", "/"])?;
    let source = source.trim();
    if !source.starts_with("/dev/") {
        return Err(EncvolError::UnsafeDisk(
            "running root must be a direct /dev partition for self-install".into(),
        ));
    }
    let lsblk = command_stdout("lsblk", &["-n", "-o", "PKNAME,PARTN,UUID,FSTYPE", source])?;
    let fields: Vec<_> = lsblk.split_whitespace().collect();
    if fields.len() < 4 || fields[0] != disk_name(disk) {
        return Err(EncvolError::UnsafeDisk(format!(
            "{disk} is not the parent disk of the running root filesystem"
        )));
    }
    let partition_number = fields[1]
        .parse::<u32>()
        .map_err(|_| EncvolError::UnsafeDisk("cannot identify root partition number".into()))?;
    let uuid = (fields[2] != "-").then(|| fields[2].to_owned());
    let fstype = fields[3].to_owned();
    let used = command_stdout("df", &["-B1", "--output=used", "/"])?;
    let used_bytes = used
        .lines()
        .filter_map(|line| line.trim().parse::<u64>().ok())
        .next()
        .ok_or_else(|| EncvolError::Unsupported("cannot estimate root filesystem usage".into()))?;
    let (partition_start_mib, partition_size_mib) = partition_bounds(disk, partition_number)?;
    Ok(RootProbe {
        identity: RootPartitionIdentity {
            path: source.to_owned(),
            partition_number,
            uuid,
            fstype,
        },
        used_bytes,
        partition_start_mib,
        partition_size_mib,
    })
}

fn parse_mib(value: &str) -> Option<u64> {
    value
        .trim()
        .strip_suffix("MiB")?
        .parse::<f64>()
        .ok()
        .map(|mib| mib.ceil() as u64)
}

fn parted_lines(disk: &str) -> Result<Vec<Vec<String>>, EncvolError> {
    let output = command_stdout("parted", &["-m", disk, "unit", "MiB", "print", "free"])?;
    Ok(output
        .lines()
        .filter(|line| !line.is_empty() && *line != "BYT;" && !line.starts_with(disk))
        .map(|line| {
            line.trim_end_matches(';')
                .split(':')
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect())
}

fn end_free_region(disk: &str) -> Result<Option<FreeRegion>, EncvolError> {
    let lines = parted_lines(disk)?;
    let Some(last) = lines.last() else {
        return Ok(None);
    };
    if !last.iter().any(|field| field == "free") || last.len() < 3 {
        return Ok(None);
    }
    Ok(Some(FreeRegion {
        size_mib: parse_mib(&last[2]).unwrap_or(0),
    }))
}

fn partition_bounds(disk: &str, partn: u32) -> Result<(u64, u64), EncvolError> {
    for fields in parted_lines(disk)? {
        if fields.first().and_then(|field| field.parse::<u32>().ok()) == Some(partn)
            && fields.len() >= 4
        {
            let start = parse_mib(&fields[1]).ok_or_else(|| {
                EncvolError::Unsupported("cannot parse root partition start".into())
            })?;
            let size = parse_mib(&fields[3]).ok_or_else(|| {
                EncvolError::Unsupported("cannot parse root partition size".into())
            })?;
            return Ok((start, size));
        }
    }
    Err(EncvolError::UnsafeDisk(
        "cannot find root partition in partition table".into(),
    ))
}

fn next_partition_number(disk: &str) -> Result<u32, EncvolError> {
    let output = command_stdout("lsblk", &["-nr", "-o", "PARTN", disk])?;
    let max = output
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    max.checked_add(1)
        .map(|number| number.max(3))
        .filter(|number| *number < 128)
        .ok_or_else(|| EncvolError::Unsupported("no free GPT partition number for staging".into()))
}

fn remote_archive_size_mib(rootfs: &RootfsDescriptor) -> Option<u64> {
    let response = ureq::head(rootfs.archive_url.as_str()).call().ok()?;
    response
        .header("content-length")?
        .parse::<u64>()
        .ok()
        .map(|bytes| bytes.div_ceil(MIB) + LIVE_ROOT_HEADROOM_MIB)
}

fn staging_requirement_mib(root: &RootProbe, source: &SelfInstallSource) -> u64 {
    match source {
        SelfInstallSource::HttpsRootfs { rootfs } => {
            remote_archive_size_mib(rootfs).unwrap_or(DEFAULT_HTTPS_STAGING_MIB)
        }
        SelfInstallSource::LiveRoot { .. } => {
            root.used_bytes.div_ceil(MIB) + LIVE_ROOT_HEADROOM_MIB
        }
    }
}

fn live_release() -> Result<String, EncvolError> {
    let data = fs::read_to_string("/etc/os-release")
        .map_err(|e| EncvolError::Unsupported(format!("cannot read live OS release: {e}")))?;
    let release = data
        .lines()
        .find_map(|line| line.strip_prefix("VERSION_CODENAME="))
        .map(|value| value.trim_matches('"').to_owned())
        .ok_or_else(|| EncvolError::Manifest("live root lacks VERSION_CODENAME".into()))?;
    if !crate::rootfs::valid_release(&release) {
        return Err(EncvolError::Manifest(
            "live root release is not a valid Debian codename".into(),
        ));
    }
    Ok(release)
}

fn choose_staging(
    disk: &str,
    root: &RootProbe,
    required_mib: u64,
) -> Result<StagingStrategy, EncvolError> {
    let staging_partition_number = next_partition_number(disk)?;
    if let Some(free) = end_free_region(disk)? {
        if free.size_mib >= required_mib {
            return Ok(StagingStrategy::ExistingFree {
                staging_partition_number,
                staging_size_mib: required_mib,
            });
        }
    }
    if root.identity.fstype != "ext4" {
        return Err(EncvolError::UnsafeDisk(format!(
            "root filesystem is {}; self-install can only shrink ext4 and needs {required_mib} MiB of unallocated end-of-disk staging space",
            root.identity.fstype
        )));
    }
    let root_used_mib = root.used_bytes.div_ceil(MIB);
    let root_target_size_mib = root_used_mib + MIN_ROOT_HEADROOM_MIB;
    if root_target_size_mib >= root.partition_size_mib {
        return Err(EncvolError::UnsafeDisk(format!(
            "root partition has insufficient free space to shrink for staging: needs {required_mib} MiB staging plus {MIN_ROOT_HEADROOM_MIB} MiB root headroom"
        )));
    }
    let free_now = end_free_region(disk)?
        .map(|free| free.size_mib)
        .unwrap_or(0);
    let shrinkable_mib = root.partition_size_mib - root_target_size_mib;
    if shrinkable_mib + free_now < required_mib {
        return Err(EncvolError::UnsafeDisk(format!(
            "insufficient disk space for staging: requires {required_mib} MiB, available after ext4 shrink is {} MiB",
            shrinkable_mib + free_now
        )));
    }
    Ok(StagingStrategy::ShrinkExt4 {
        staging_partition_number,
        root_target_size_mib,
        root_partition_end_mib: root.partition_start_mib + root_target_size_mib,
        staging_size_mib: required_mib,
    })
}

fn default_route_interface() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let words: Vec<_> = text.split_whitespace().collect();
    words.windows(2).find_map(|window| {
        if window[0] == "dev" {
            Some(window[1].to_owned())
        } else {
            None
        }
    })
}

fn dns() -> Vec<String> {
    fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            line.strip_prefix("nameserver ")
                .map(str::trim)
                .map(str::to_owned)
        })
        .collect()
}

fn host_network() -> Option<NetworkConfig> {
    let interface = default_route_interface()?;
    let link = fs::read_to_string(format!("/sys/class/net/{interface}/address"))
        .ok()
        .map(|value| value.trim().to_owned());
    Some(NetworkConfig {
        interface,
        mac_address: link,
        mode: NetworkMode::Dhcp,
        addresses: vec![],
        gateway: None,
        dns: dns(),
    })
}

pub fn prepare(
    request: SelfInstallRequest,
) -> Result<(SelfInstallManifest, SelfInstallPlan, HostCapabilities), EncvolError> {
    safety::validate_disk_path(&request.disk)?;
    if request.use_live_root == request.rootfs_descriptor.is_some() {
        return Err(EncvolError::Manifest(
            "choose exactly one self-install source: --use-live-root or --rootfs-descriptor".into(),
        ));
    }
    let (handoff, capabilities) = self_install_handoff();
    if handoff == Handoff::Unsupported {
        return Err(EncvolError::Unsupported(
            "self-install requires GRUB one-shot boot or UEFI BootNext; kexec is not used".into(),
        ));
    }
    let source = if let Some(descriptor) = request.rootfs_descriptor {
        let bytes = bundle::download(&descriptor)?;
        let rootfs: RootfsDescriptor = serde_json::from_slice(&bytes)
            .map_err(|_| EncvolError::Manifest("rootfs descriptor is not valid JSON".into()))?;
        rootfs.validate()?;
        SelfInstallSource::HttpsRootfs { rootfs }
    } else {
        SelfInstallSource::LiveRoot {
            format: ArchiveFormat::TarZst,
            release: live_release()?,
        }
    };
    let root = root_probe(&request.disk)?;
    let required_mib = staging_requirement_mib(&root, &source);
    let staging = choose_staging(&request.disk, &root, required_mib)?;
    let network = host_network().ok_or_else(|| {
        EncvolError::Unsupported("could not capture active network configuration".into())
    })?;
    let manifest = SelfInstallManifest {
        schema_version: 1,
        mode: "self-install".into(),
        target_disk: request.disk,
        source,
        original_root: root.identity,
        staging,
        tang_url: request.tang_url,
        tang_thumbprint: request.tang_thumbprint,
        recovery_authorized_key: request.recovery_authorized_key,
        network,
        layout: Some(Layout {
            swap_mib: request.swap_mib,
            data_volume: request.data_volume,
        }),
    };
    manifest.validate()?;
    let source_label = match &manifest.source {
        SelfInstallSource::HttpsRootfs { .. } => "https-rootfs",
        SelfInstallSource::LiveRoot { .. } => "live-root",
    };
    let plan = SelfInstallPlan {
        target_disk: manifest.target_disk.clone(),
        handoff,
        root_partition: manifest.original_root.clone(),
        source: source_label.into(),
        staging: manifest.staging.clone(),
        steps: vec![
            "boot the embedded RAM installer with encvol.self_install=1".into(),
            "revalidate the original root partition before touching the partition table".into(),
            "create an ext4 staging partition from end-of-disk free space or by shrinking ext4 root".into(),
            "download and verify the rootfs archive, or capture the old root read-only into staging".into(),
            "wipe only non-staging partitions, install the encrypted LUKS/LVM system, then remove staging and grow root".into(),
        ],
    };
    Ok((manifest, plan, capabilities))
}
