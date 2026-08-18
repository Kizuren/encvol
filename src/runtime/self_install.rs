use crate::{
    bundle,
    manifest::{InstallationManifest, SelfInstallManifest, SelfInstallSource, StagingStrategy},
    rootfs::{self, ArchiveFormat, RootfsDescriptor},
    safety, EncvolError,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use url::Url;

use super::{
    command::run_command,
    config::{prepare_target_runtime_directories, write_root_configuration},
    environment::{command_line_has_self_install_flag, verify_runtime_environment},
    install::{
        bind_chroot_mounts, bind_tang_slot, create_mountpoints, install_bootloader,
        install_target_packages,
    },
    layout::{logical_volume, partition},
    Firmware, RuntimeOptions,
};

const STAGING_MOUNT: &str = "/encvol-staging";
const OLD_ROOT_MOUNT: &str = "/encvol-old-root";

#[derive(Debug, Clone)]
struct StagedRootfs {
    descriptor: RootfsDescriptor,
    archive: PathBuf,
}

fn checked_output(program: &str, args: &[&str]) -> Result<String, EncvolError> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

fn parse_mib(value: &str) -> Option<u64> {
    value
        .trim()
        .strip_suffix("MiB")?
        .parse::<f64>()
        .ok()
        .map(|mib| mib.ceil() as u64)
}

fn parted_lines(disk: &str) -> Result<Vec<Vec<String>>, EncvolError> {
    let output = checked_output("parted", &["-m", disk, "unit", "MiB", "print", "free"])?;
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

fn end_free_start_mib(disk: &str, required_mib: u64) -> Result<u64, EncvolError> {
    let lines = parted_lines(disk)?;
    let Some(last) = lines.last() else {
        return Err(EncvolError::UnsafeDisk(
            "partition table has no free staging space".into(),
        ));
    };
    if !last.iter().any(|field| field == "free") || last.len() < 3 {
        return Err(EncvolError::UnsafeDisk(
            "end-of-disk free staging space is not available".into(),
        ));
    }
    let start = parse_mib(&last[0]).unwrap_or(0);
    let size = parse_mib(&last[2]).unwrap_or(0);
    if size < required_mib {
        return Err(EncvolError::UnsafeDisk(format!(
            "insufficient staging space: requires {required_mib} MiB, found {size} MiB"
        )));
    }
    Ok(start)
}

fn partition_start_mib(disk: &str, partn: u32) -> Result<u64, EncvolError> {
    for fields in parted_lines(disk)? {
        if fields.first().and_then(|field| field.parse::<u32>().ok()) == Some(partn)
            && fields.len() >= 3
        {
            return parse_mib(&fields[1]).ok_or_else(|| {
                EncvolError::Unsupported("cannot parse staging partition start".into())
            });
        }
    }
    Err(EncvolError::UnsafeDisk(
        "cannot find staging partition in partition table".into(),
    ))
}

fn existing_partition_numbers(disk: &str) -> Result<Vec<u32>, EncvolError> {
    let output = checked_output("lsblk", &["-nr", "-o", "PARTN", disk])?;
    Ok(output
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .collect())
}

fn verify_original_root(manifest: &SelfInstallManifest) -> Result<(), EncvolError> {
    let output = checked_output(
        "lsblk",
        &[
            "-n",
            "-o",
            "PARTN,UUID,FSTYPE",
            &manifest.original_root.path,
        ],
    )?;
    let fields: Vec<_> = output.split_whitespace().collect();
    if fields.len() < 3 {
        return Err(EncvolError::UnsafeDisk(
            "cannot revalidate original root partition".into(),
        ));
    }
    let partn = fields[0]
        .parse::<u32>()
        .map_err(|_| EncvolError::UnsafeDisk("cannot revalidate root partition number".into()))?;
    if partn != manifest.original_root.partition_number
        || manifest
            .original_root
            .uuid
            .as_deref()
            .is_some_and(|uuid| uuid != fields[1])
        || manifest.original_root.fstype != fields[2]
    {
        return Err(EncvolError::UnsafeDisk(
            "original root partition identity changed since staging".into(),
        ));
    }
    Ok(())
}

fn create_staging_partition(manifest: &SelfInstallManifest) -> Result<u32, EncvolError> {
    let (staging_partition_number, staging_size_mib) = match &manifest.staging {
        StagingStrategy::ExistingFree {
            staging_partition_number,
            staging_size_mib,
        }
        | StagingStrategy::ShrinkExt4 {
            staging_partition_number,
            staging_size_mib,
            ..
        } => (*staging_partition_number, *staging_size_mib),
    };
    match &manifest.staging {
        StagingStrategy::ExistingFree { .. } => {}
        StagingStrategy::ShrinkExt4 {
            root_target_size_mib,
            root_partition_end_mib,
            ..
        } => {
            if manifest.original_root.fstype != "ext4" {
                return Err(EncvolError::UnsafeDisk(
                    "only ext4 roots can be shrunk for self-install staging".into(),
                ));
            }
            run_command(
                &[
                    "e2fsck".into(),
                    "-f".into(),
                    manifest.original_root.path.clone(),
                ],
                None,
            )?;
            run_command(
                &[
                    "resize2fs".into(),
                    manifest.original_root.path.clone(),
                    format!("{root_target_size_mib}M"),
                ],
                None,
            )?;
            run_command(
                &[
                    "parted".into(),
                    "-s".into(),
                    manifest.target_disk.clone(),
                    "unit".into(),
                    "MiB".into(),
                    "resizepart".into(),
                    manifest.original_root.partition_number.to_string(),
                    root_partition_end_mib.to_string(),
                ],
                None,
            )?;
            run_command(&["partprobe".into(), manifest.target_disk.clone()], None)?;
        }
    }
    let start_mib = end_free_start_mib(&manifest.target_disk, staging_size_mib)?;
    run_command(
        &[
            "sgdisk".into(),
            format!("--new={staging_partition_number}:{start_mib}MiB:+{staging_size_mib}MiB"),
            format!("--typecode={staging_partition_number}:8300"),
            manifest.target_disk.clone(),
        ],
        None,
    )?;
    run_command(&["partprobe".into(), manifest.target_disk.clone()], None)?;
    let staging_partition = partition(&manifest.target_disk, staging_partition_number);
    run_command(
        &["mkfs.ext4".into(), "-F".into(), staging_partition.clone()],
        None,
    )?;
    fs::create_dir_all(STAGING_MOUNT)
        .map_err(|e| EncvolError::Unsupported(format!("cannot create staging mountpoint: {e}")))?;
    run_command(
        &["mount".into(), staging_partition, STAGING_MOUNT.into()],
        None,
    )?;
    Ok(staging_partition_number)
}

fn live_root_pack_command(root: &Path, output: &Path, format: ArchiveFormat) -> Vec<String> {
    let mut command = rootfs::pack_command(root, output, format);
    let insert_at = command
        .iter()
        .position(|arg| arg == "--directory")
        .unwrap_or(command.len());
    command.insert(insert_at, "--exclude=./boot/encvol/*".into());
    command.insert(insert_at, "--exclude=./mnt/*".into());
    command
}

fn stage_rootfs(manifest: &SelfInstallManifest) -> Result<StagedRootfs, EncvolError> {
    match &manifest.source {
        SelfInstallSource::HttpsRootfs { rootfs } => {
            let archive = PathBuf::from(STAGING_MOUNT).join("rootfs.archive");
            let actual = bundle::download_to_path(&rootfs.archive_url, &archive)?;
            if actual != rootfs.sha256.to_ascii_lowercase() {
                let _ = fs::remove_file(&archive);
                return Err(EncvolError::Verification(
                    "rootfs SHA-256 did not verify in staging".into(),
                ));
            }
            Ok(StagedRootfs {
                descriptor: rootfs.clone(),
                archive,
            })
        }
        SelfInstallSource::LiveRoot { format, release } => {
            fs::create_dir_all(OLD_ROOT_MOUNT).map_err(|e| {
                EncvolError::Unsupported(format!("cannot create old-root mountpoint: {e}"))
            })?;
            run_command(
                &[
                    "mount".into(),
                    "--read-only".into(),
                    manifest.original_root.path.clone(),
                    OLD_ROOT_MOUNT.into(),
                ],
                None,
            )?;
            rootfs::validate_workspace(Path::new(OLD_ROOT_MOUNT))?;
            let archive = PathBuf::from(STAGING_MOUNT).join(match format {
                ArchiveFormat::Tar => "live-root.tar",
                ArchiveFormat::TarZst => "live-root.tar.zst",
            });
            let result = run_command(
                &live_root_pack_command(Path::new(OLD_ROOT_MOUNT), &archive, *format),
                None,
            );
            let unmount = run_command(&["umount".into(), OLD_ROOT_MOUNT.into()], None);
            result?;
            unmount?;
            let sha256 = bundle::sha256_file(&archive)?;
            let descriptor = RootfsDescriptor {
                schema_version: rootfs::ROOTFS_SCHEMA_VERSION,
                archive_url: Url::parse("https://self-install.invalid/live-root").unwrap(),
                sha256,
                release: release.clone(),
                architecture: "amd64".into(),
                provides: rootfs::REQUIRED_CAPABILITIES
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                format: *format,
            };
            descriptor.validate()?;
            Ok(StagedRootfs {
                descriptor,
                archive,
            })
        }
    }
}

fn create_preserved_layout(
    manifest: &InstallationManifest,
    firmware: Firmware,
    recovery_passphrase: &[u8],
    staging_partition_number: u32,
) -> Result<(), EncvolError> {
    let staging_start_mib = partition_start_mib(&manifest.target_disk, staging_partition_number)?;
    eprintln!(
        "encvol: staging rootfs is verified; destructive repartitioning begins now. If this fails, boot provider recovery media and inspect console logs."
    );
    for partn in existing_partition_numbers(&manifest.target_disk)? {
        if partn != staging_partition_number {
            run_command(
                &[
                    "sgdisk".into(),
                    format!("--delete={partn}"),
                    manifest.target_disk.clone(),
                ],
                None,
            )?;
        }
    }
    let mut partition_command = vec!["sgdisk".into()];
    match firmware {
        Firmware::Uefi => {
            partition_command.extend(["--new=1:1MiB:+512MiB".into(), "--typecode=1:ef00".into()])
        }
        Firmware::Bios => {
            partition_command.extend(["--new=1:1MiB:+1MiB".into(), "--typecode=1:ef02".into()])
        }
    }
    partition_command.extend([
        format!("--new=2:0:{}MiB", staging_start_mib.saturating_sub(1)),
        "--typecode=2:8309".into(),
        manifest.target_disk.clone(),
    ]);
    run_command(&partition_command, None)?;
    run_command(&["partprobe".into(), manifest.target_disk.clone()], None)?;
    let crypt = partition(&manifest.target_disk, 2);
    for command in [
        vec![
            "wipefs".into(),
            "--all".into(),
            "--force".into(),
            crypt.clone(),
        ],
        vec![
            "cryptsetup".into(),
            "luksFormat".into(),
            "--type".into(),
            "luks2".into(),
            crypt.clone(),
            "--key-file=-".into(),
        ],
        vec![
            "cryptsetup".into(),
            "open".into(),
            crypt,
            "encvol_crypt".into(),
            "--key-file=-".into(),
        ],
        vec!["pvcreate".into(), "/dev/mapper/encvol_crypt".into()],
        vec![
            "vgcreate".into(),
            "encvol".into(),
            "/dev/mapper/encvol_crypt".into(),
        ],
        vec![
            "lvcreate".into(),
            "--name".into(),
            "swap".into(),
            "--size".into(),
            format!(
                "{}M",
                manifest
                    .layout
                    .as_ref()
                    .map(|layout| layout.swap_mib)
                    .unwrap_or(1024)
            ),
            "encvol".into(),
        ],
    ] {
        let input = if command[0] == "cryptsetup" {
            Some(recovery_passphrase)
        } else {
            None
        };
        run_command(&command, input)?;
    }
    if manifest
        .layout
        .as_ref()
        .is_some_and(|layout| layout.data_volume)
    {
        run_command(
            &[
                "lvcreate".into(),
                "--name".into(),
                "root".into(),
                "--extents".into(),
                "70%FREE".into(),
                "encvol".into(),
            ],
            None,
        )?;
        run_command(
            &[
                "lvcreate".into(),
                "--name".into(),
                "data".into(),
                "--extents".into(),
                "100%FREE".into(),
                "encvol".into(),
            ],
            None,
        )?;
    } else {
        run_command(
            &[
                "lvcreate".into(),
                "--name".into(),
                "root".into(),
                "--extents".into(),
                "100%FREE".into(),
                "encvol".into(),
            ],
            None,
        )?;
    }
    run_command(
        &["mkfs.ext4".into(), "-F".into(), logical_volume("root")],
        None,
    )?;
    run_command(&["mkswap".into(), logical_volume("swap")], None)?;
    run_command(
        &["mount".into(), logical_volume("root"), "/target".into()],
        None,
    )?;
    if manifest
        .layout
        .as_ref()
        .is_some_and(|layout| layout.data_volume)
    {
        run_command(
            &["mkfs.ext4".into(), "-F".into(), logical_volume("data")],
            None,
        )?;
        fs::create_dir_all("/target/data")
            .map_err(|e| EncvolError::Unsupported(format!("cannot create data mountpoint: {e}")))?;
        run_command(
            &[
                "mount".into(),
                logical_volume("data"),
                "/target/data".into(),
            ],
            None,
        )?;
    }
    if firmware == Firmware::Uefi {
        fs::create_dir_all("/target/boot/efi")
            .map_err(|e| EncvolError::Unsupported(format!("cannot create ESP mountpoint: {e}")))?;
        run_command(
            &[
                "mkfs.fat".into(),
                "-F32".into(),
                partition(&manifest.target_disk, 1),
            ],
            None,
        )?;
        run_command(
            &[
                "mount".into(),
                partition(&manifest.target_disk, 1),
                "/target/boot/efi".into(),
            ],
            None,
        )?;
    }
    Ok(())
}

fn partition_first_sector(disk: &str, partn: u32) -> Result<String, EncvolError> {
    let output = checked_output("sgdisk", &["-i", &partn.to_string(), disk])?;
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("First sector:"))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .ok_or_else(|| EncvolError::Unsupported("cannot find LUKS partition start sector".into()))
}

fn remove_staging_and_grow(disk: &str, staging_partition_number: u32) -> Result<(), EncvolError> {
    let luks_start = partition_first_sector(disk, 2)?;
    let _ = fs::remove_dir_all("/target/boot/encvol");
    run_command(&["umount".into(), STAGING_MOUNT.into()], None)?;
    run_command(
        &[
            "sgdisk".into(),
            format!("--delete={staging_partition_number}"),
            disk.into(),
        ],
        None,
    )?;
    run_command(&["sgdisk".into(), "--delete=2".into(), disk.into()], None)?;
    run_command(
        &[
            "sgdisk".into(),
            format!("--new=2:{luks_start}:0"),
            "--typecode=2:8309".into(),
            disk.into(),
        ],
        None,
    )?;
    run_command(&["partprobe".into(), disk.into()], None)?;
    run_command(
        &["cryptsetup".into(), "resize".into(), "encvol_crypt".into()],
        None,
    )?;
    run_command(
        &["pvresize".into(), "/dev/mapper/encvol_crypt".into()],
        None,
    )?;
    run_command(
        &[
            "lvextend".into(),
            "--extents".into(),
            "+100%FREE".into(),
            logical_volume("root"),
        ],
        None,
    )?;
    run_command(&["resize2fs".into(), logical_volume("root")], None)
}

pub fn run(
    manifest: &SelfInstallManifest,
    options: &RuntimeOptions,
    recovery_passphrase: &[u8],
) -> Result<(), EncvolError> {
    safety::validate_disk_path(&manifest.target_disk)?;
    manifest.validate()?;
    verify_runtime_environment(options)?;
    if !options.allow_non_ram && !command_line_has_self_install_flag() {
        return Err(EncvolError::UnsafeDisk(
            "self-install must be booted with encvol.self_install=1".into(),
        ));
    }
    if !options.execute {
        return Ok(());
    }

    verify_original_root(manifest)?;
    let staging_partition_number = create_staging_partition(manifest)?;
    let staged = stage_rootfs(manifest)?;
    if bundle::sha256_file(&staged.archive)? != staged.descriptor.sha256.to_ascii_lowercase() {
        return Err(EncvolError::Verification(
            "staged rootfs SHA-256 changed before install".into(),
        ));
    }
    let install_manifest = manifest.installation_manifest(staged.descriptor);
    create_mountpoints()?;
    create_preserved_layout(
        &install_manifest,
        options.firmware,
        recovery_passphrase,
        staging_partition_number,
    )?;
    run_command(
        &rootfs::extraction_command(
            install_manifest.rootfs.format,
            &staged.archive,
            Path::new("/target"),
        ),
        None,
    )?;
    prepare_target_runtime_directories(Path::new("/target"))?;
    write_root_configuration(&install_manifest, options.firmware)?;
    bind_chroot_mounts()?;
    install_target_packages(options.firmware)?;
    bind_tang_slot(&install_manifest, recovery_passphrase)?;
    install_bootloader(&install_manifest, options.firmware)?;
    remove_staging_and_grow(&install_manifest.target_disk, staging_partition_number)
}
