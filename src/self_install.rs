use crate::{
    bundle,
    handoff::{select_handoff, Handoff, HostCapabilities},
    manifest::{
        Layout, RootPartitionIdentity, SelfInstallManifest, SelfInstallSource,
        ShrinkPartitionIdentity, StagingStrategy,
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
    pub install_mode: InstallMode,
    pub source: String,
    pub staging: StagingStrategy,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallMode {
    RootDiskInPlace,
    NonRootDiskInPlace,
    ExternalEmptyOrFreeDisk,
    BlockedMountedNonRoot,
}

#[derive(Debug, Clone, Serialize)]
pub struct MountedPartition {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallModePlan {
    pub mode: InstallMode,
    pub root_partition: RootPartitionIdentity,
    pub staging: Option<StagingStrategy>,
    pub mounted: Vec<MountedPartition>,
}

#[derive(Debug, Clone)]
pub struct SelfInstallRequest {
    pub disk: String,
    pub rootfs_descriptor: Option<Url>,
    pub tang_url: Url,
    pub tang_thumbprint: String,
    pub recovery_authorized_key: String,
    pub swap_mib: u64,
    pub data_volume: bool,
}

#[derive(Debug, Clone)]
struct RootProbe {
    identity: RootPartitionIdentity,
    parent_disk: String,
    used_bytes: u64,
    partition_start_mib: u64,
    partition_size_mib: u64,
}

#[derive(Debug, Clone)]
struct FreeRegion {
    size_mib: u64,
}

#[derive(Debug, Clone)]
struct ShrinkCandidate {
    identity: ShrinkPartitionIdentity,
    partition_start_mib: u64,
    partition_size_mib: u64,
    minimum_size_mib: u64,
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

fn qemu_direct_kexec_requested() -> bool {
    std::env::var_os("ENCVOL_QEMU_DIRECT_KEXEC").is_some()
        && fs::read_to_string("/proc/cmdline")
            .map(|cmdline| {
                cmdline
                    .split_whitespace()
                    .any(|arg| arg == "encvol.qemu.source=1")
            })
            .unwrap_or(false)
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
    let handoff = if qemu_direct_kexec_requested() && capabilities.kexec {
        Handoff::Kexec
    } else {
        select_handoff(&capabilities)
    };
    (handoff, capabilities)
}

fn disk_name(disk: &str) -> &str {
    Path::new(disk)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
}

fn partition_number_from_device(path: &str) -> Result<u32, EncvolError> {
    let name = disk_name(path);
    let value = fs::read_to_string(format!("/sys/class/block/{name}/partition"))
        .map_err(|_| EncvolError::UnsafeDisk("cannot identify partition number".into()))?;
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| EncvolError::UnsafeDisk("cannot identify partition number".into()))
}

fn partition_path(disk: &str, partn: u32) -> String {
    if disk_name(disk)
        .as_bytes()
        .last()
        .is_some_and(u8::is_ascii_digit)
    {
        format!("{disk}p{partn}")
    } else {
        format!("{disk}{partn}")
    }
}

fn live_root_probe() -> Result<RootProbe, EncvolError> {
    let source = command_stdout("findmnt", &["-n", "-o", "SOURCE", "--target", "/"])?;
    let source = source.trim();
    if !source.starts_with("/dev/") {
        return Err(EncvolError::UnsafeDisk(
            "running root must be a direct /dev partition for in-place install".into(),
        ));
    }
    let parent = command_stdout("lsblk", &["-n", "-o", "PKNAME", source])?;
    let parent = parent.trim();
    if parent.is_empty() {
        return Err(EncvolError::UnsafeDisk(
            "cannot identify running root parent disk".into(),
        ));
    }
    let partition_number = partition_number_from_device(source)?;
    let uuid = command_stdout("blkid", &["-s", "UUID", "-o", "value", source])
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let fstype = command_stdout("findmnt", &["-n", "-o", "FSTYPE", "--target", "/"])?;
    let fstype = fstype.trim().to_owned();
    let used = command_stdout("df", &["-B1", "--output=used", "/"])?;
    let used_bytes = used
        .lines()
        .filter_map(|line| line.trim().parse::<u64>().ok())
        .next()
        .ok_or_else(|| EncvolError::Unsupported("cannot estimate root filesystem usage".into()))?;
    let parent_disk = format!("/dev/{parent}");
    let (partition_start_mib, partition_size_mib) =
        partition_bounds(&parent_disk, partition_number)?;
    Ok(RootProbe {
        identity: RootPartitionIdentity {
            path: source.to_owned(),
            partition_number,
            uuid,
            fstype,
        },
        parent_disk,
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

fn final_partition(disk: &str) -> Result<Option<(u32, u64, u64)>, EncvolError> {
    let mut partitions = Vec::new();
    for fields in parted_lines(disk)? {
        if let Some(partn) = fields.first().and_then(|field| field.parse::<u32>().ok()) {
            if fields.len() >= 4 {
                let start = parse_mib(&fields[1]).ok_or_else(|| {
                    EncvolError::Unsupported("cannot parse partition start".into())
                })?;
                let end = parse_mib(&fields[2])
                    .ok_or_else(|| EncvolError::Unsupported("cannot parse partition end".into()))?;
                let size = parse_mib(&fields[3]).ok_or_else(|| {
                    EncvolError::Unsupported("cannot parse partition size".into())
                })?;
                partitions.push((partn, start, end, size));
            }
        }
    }
    Ok(partitions
        .into_iter()
        .max_by_key(|(_, _, end_mib, _)| *end_mib)
        .map(|(partn, start, _, size)| (partn, start, size)))
}

fn partition_fstype(path: &str) -> Result<String, EncvolError> {
    for args in [
        &["-s", "TYPE", "-o", "value", path][..],
        &["-p", "-s", "TYPE", "-o", "value", path][..],
    ] {
        if let Ok(output) = command_stdout("blkid", args) {
            let fstype = output.trim();
            if !fstype.is_empty() {
                return Ok(fstype.to_owned());
            }
        }
    }
    let output = command_stdout("lsblk", &["-n", "-o", "FSTYPE", path])?;
    Ok(output.trim().to_owned())
}

fn ext4_minimum_size_mib(path: &str) -> Result<u64, EncvolError> {
    let tune = command_stdout("tune2fs", &["-l", path])?;
    let block_size = tune
        .lines()
        .find_map(|line| line.trim().strip_prefix("Block size:"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .ok_or_else(|| EncvolError::Unsupported("cannot determine ext4 block size".into()))?;
    let output = Command::new("resize2fs")
        .args(["-P", path])
        .output()
        .map_err(|e| EncvolError::Unsupported(format!("cannot run resize2fs: {e}")))?;
    if !output.status.success() {
        return Err(EncvolError::Unsupported(format!(
            "resize2fs -P failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let minimum_blocks = text
        .split_whitespace()
        .rev()
        .find_map(|word| word.parse::<u64>().ok())
        .ok_or_else(|| EncvolError::Unsupported("cannot determine ext4 minimum size".into()))?;
    Ok((minimum_blocks * block_size).div_ceil(MIB))
}

fn non_root_shrink_candidate(disk: &str) -> Result<Option<ShrinkCandidate>, EncvolError> {
    let Some((partition_number, partition_start_mib, partition_size_mib)) = final_partition(disk)?
    else {
        return Ok(None);
    };
    let path = partition_path(disk, partition_number);
    let fstype = partition_fstype(&path)?;
    if fstype != "ext4" {
        return Ok(Some(ShrinkCandidate {
            identity: ShrinkPartitionIdentity {
                path,
                partition_number,
                fstype,
            },
            partition_start_mib,
            partition_size_mib,
            minimum_size_mib: partition_size_mib,
        }));
    }
    Ok(Some(ShrinkCandidate {
        identity: ShrinkPartitionIdentity {
            path: path.clone(),
            partition_number,
            fstype,
        },
        partition_start_mib,
        partition_size_mib,
        minimum_size_mib: ext4_minimum_size_mib(&path)?,
    }))
}

fn next_partition_number(disk: &str) -> Result<u32, EncvolError> {
    let output = command_stdout("lsblk", &["-nr", "-o", "NAME,TYPE", disk])?;
    let max = output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            (fields.next() == Some("part")).then(|| {
                fs::read_to_string(format!("/sys/class/block/{name}/partition"))
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok())
            })?
        })
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

fn staging_from_existing_free(
    disk: &str,
    required_mib: u64,
) -> Result<Option<StagingStrategy>, EncvolError> {
    let staging_partition_number = next_partition_number(disk)?;
    if let Some(free) = end_free_region(disk)? {
        if free.size_mib >= required_mib {
            return Ok(Some(StagingStrategy::ExistingFree {
                staging_partition_number,
                staging_size_mib: required_mib,
            }));
        }
    }
    Ok(None)
}

fn choose_root_disk_staging(
    disk: &str,
    root: &RootProbe,
    required_mib: u64,
) -> Result<StagingStrategy, EncvolError> {
    if let Some(staging) = staging_from_existing_free(disk, required_mib)? {
        return Ok(staging);
    }
    let staging_partition_number = next_partition_number(disk)?;
    if root.identity.fstype != "ext4" {
        return Err(EncvolError::UnsafeDisk(format!(
            "root filesystem is {}; in-place install can only shrink ext4 and needs {required_mib} MiB of unallocated end-of-disk staging space",
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
        shrink_partition: None,
    })
}

fn choose_non_root_staging(disk: &str, required_mib: u64) -> Result<StagingStrategy, EncvolError> {
    if let Some(staging) = staging_from_existing_free(disk, required_mib)? {
        return Ok(staging);
    }
    let Some(candidate) = non_root_shrink_candidate(disk)? else {
        return Err(EncvolError::UnsafeDisk(format!(
            "insufficient disk space for staging: requires {required_mib} MiB and the target disk has no shrinkable final partition"
        )));
    };
    choose_non_root_shrink_staging(
        next_partition_number(disk)?,
        required_mib,
        end_free_region(disk)?
            .map(|free| free.size_mib)
            .unwrap_or(0),
        candidate,
    )
}

fn choose_non_root_shrink_staging(
    staging_partition_number: u32,
    required_mib: u64,
    free_now: u64,
    candidate: ShrinkCandidate,
) -> Result<StagingStrategy, EncvolError> {
    if candidate.identity.fstype != "ext4" {
        return Err(EncvolError::UnsafeDisk(format!(
            "final target partition is {}; in-place install can only shrink ext4 and needs {required_mib} MiB of unallocated end-of-disk staging space",
            candidate.identity.fstype
        )));
    }
    let target_size_mib = candidate.minimum_size_mib + MIN_ROOT_HEADROOM_MIB;
    if target_size_mib >= candidate.partition_size_mib {
        return Err(EncvolError::UnsafeDisk(format!(
            "final ext4 partition has insufficient free space to shrink for staging: needs {required_mib} MiB staging plus {MIN_ROOT_HEADROOM_MIB} MiB filesystem headroom"
        )));
    }
    let shrinkable_mib = candidate.partition_size_mib - target_size_mib;
    if shrinkable_mib + free_now < required_mib {
        return Err(EncvolError::UnsafeDisk(format!(
            "insufficient disk space for staging: requires {required_mib} MiB, available after ext4 shrink is {} MiB",
            shrinkable_mib + free_now
        )));
    }
    Ok(StagingStrategy::ShrinkExt4 {
        staging_partition_number,
        root_target_size_mib: target_size_mib,
        root_partition_end_mib: candidate.partition_start_mib + target_size_mib,
        staging_size_mib: required_mib,
        shrink_partition: Some(candidate.identity),
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

fn mounted_partitions(disk: &str) -> Vec<MountedPartition> {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let source = fields.next()?.to_owned();
            let target = fields.next()?.to_owned();
            safety::is_mounted_source(disk, std::slice::from_ref(&source))
                .then_some(MountedPartition { source, target })
        })
        .collect()
}

pub fn plan_mode_with_source(
    disk: &str,
    source: &SelfInstallSource,
) -> Result<InstallModePlan, EncvolError> {
    safety::validate_disk_path(disk)?;
    let root = live_root_probe()?;
    let required_mib = staging_requirement_mib(&root, source);
    if root.parent_disk == disk {
        let staging = choose_root_disk_staging(disk, &root, required_mib)?;
        return Ok(InstallModePlan {
            mode: InstallMode::RootDiskInPlace,
            root_partition: root.identity,
            staging: Some(staging),
            mounted: vec![],
        });
    }
    let mounted = mounted_partitions(disk);
    if !mounted.is_empty() {
        return Ok(InstallModePlan {
            mode: InstallMode::BlockedMountedNonRoot,
            root_partition: root.identity,
            staging: None,
            mounted,
        });
    }
    let staging = choose_non_root_staging(disk, required_mib)?;
    Ok(InstallModePlan {
        mode: InstallMode::NonRootDiskInPlace,
        root_partition: root.identity,
        staging: Some(staging),
        mounted: vec![],
    })
}

pub fn plan_default_mode(disk: &str) -> Result<InstallModePlan, EncvolError> {
    let source = SelfInstallSource::LiveRoot {
        format: ArchiveFormat::TarZst,
        release: live_release()?,
    };
    plan_mode_with_source(disk, &source)
}

pub fn is_running_root_parent(disk: &str) -> Result<bool, EncvolError> {
    safety::validate_disk_path(disk)?;
    Ok(live_root_probe()?.parent_disk == disk)
}

pub fn prepare(
    request: SelfInstallRequest,
) -> Result<(SelfInstallManifest, SelfInstallPlan, HostCapabilities), EncvolError> {
    safety::validate_disk_path(&request.disk)?;
    let (handoff, capabilities) = self_install_handoff();
    if handoff == Handoff::Unsupported {
        return Err(EncvolError::Unsupported(
            "in-place install requires GRUB one-shot boot or UEFI BootNext; kexec is not used"
                .into(),
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
    let mode_plan = plan_mode_with_source(&request.disk, &source)?;
    if mode_plan.mode == InstallMode::BlockedMountedNonRoot {
        let details = mode_plan
            .mounted
            .iter()
            .map(|mount| format!("{} on {}", mount.source, mount.target))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(EncvolError::UnsafeDisk(format!(
            "target disk has mounted partitions: {details}; unmount them first, for example: umount <mount-target>"
        )));
    }
    let staging = mode_plan
        .staging
        .clone()
        .ok_or_else(|| EncvolError::UnsafeDisk("no in-place staging plan was selected".into()))?;
    let network = host_network().ok_or_else(|| {
        EncvolError::Unsupported("could not capture active network configuration".into())
    })?;
    let manifest = SelfInstallManifest {
        schema_version: 1,
        mode: "self-install".into(),
        target_disk: request.disk,
        source,
        original_root: mode_plan.root_partition.clone(),
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
        install_mode: mode_plan.mode,
        source: source_label.into(),
        staging: manifest.staging.clone(),
        steps: vec![
            "boot the embedded RAM installer with encvol.self_install=1".into(),
            "revalidate the original root partition before touching the partition table".into(),
            "create an ext4 staging partition from end-of-disk free space or by shrinking the final ext4 partition".into(),
            "download and verify the rootfs archive, or capture the old root read-only into staging".into(),
            "wipe only non-staging partitions, install the encrypted LUKS/LVM system, then remove staging and grow root".into(),
        ],
    };
    Ok((manifest, plan, capabilities))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(fstype: &str, size_mib: u64, minimum_size_mib: u64) -> ShrinkCandidate {
        ShrinkCandidate {
            identity: ShrinkPartitionIdentity {
                path: "/dev/vdb1".into(),
                partition_number: 1,
                fstype: fstype.into(),
            },
            partition_start_mib: 1,
            partition_size_mib: size_mib,
            minimum_size_mib,
        }
    }

    #[test]
    fn non_root_final_ext4_selects_shrink_staging() {
        let staging =
            choose_non_root_shrink_staging(3, 2048, 0, candidate("ext4", 8192, 2048)).unwrap();
        match staging {
            StagingStrategy::ShrinkExt4 {
                staging_partition_number,
                root_target_size_mib,
                root_partition_end_mib,
                staging_size_mib,
                shrink_partition: Some(shrink),
            } => {
                assert_eq!(staging_partition_number, 3);
                assert_eq!(root_target_size_mib, 4096);
                assert_eq!(root_partition_end_mib, 4097);
                assert_eq!(staging_size_mib, 2048);
                assert_eq!(shrink.path, "/dev/vdb1");
            }
            other => panic!("unexpected staging strategy: {other:?}"),
        }
    }

    #[test]
    fn non_root_final_non_ext4_is_rejected() {
        let err =
            choose_non_root_shrink_staging(3, 2048, 0, candidate("xfs", 8192, 2048)).unwrap_err();
        assert!(err.to_string().contains("final target partition is xfs"));
    }

    #[test]
    fn non_root_ext4_without_enough_space_is_rejected() {
        let err =
            choose_non_root_shrink_staging(3, 4096, 0, candidate("ext4", 6144, 3072)).unwrap_err();
        assert!(err.to_string().contains("insufficient"));
    }
}
