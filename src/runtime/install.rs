use crate::{
    bundle, manifest::InstallationManifest, rootfs::extraction_command, safety, EncvolError,
};
use std::{fs, os::unix::fs::FileTypeExt, path::Path};

use super::{
    command::run_command,
    config::{prepare_target_runtime_directories, tang_config, write_root_configuration},
    environment::verify_runtime_environment,
    layout::{logical_volume, partition, runtime_commands},
    Firmware, RuntimeOptions,
};

fn packages(firmware: Firmware) -> &'static [&'static str] {
    match firmware {
        Firmware::Uefi => &[
            "linux-image-amd64",
            "grub-efi-amd64",
            "shim-signed",
            "cryptsetup",
            "lvm2",
            "clevis",
            "clevis-luks",
            "clevis-initramfs",
            "dropbear-initramfs",
        ],
        Firmware::Bios => &[
            "linux-image-amd64",
            "grub-pc",
            "cryptsetup",
            "lvm2",
            "clevis",
            "clevis-luks",
            "clevis-initramfs",
            "dropbear-initramfs",
        ],
    }
}

fn verify_target_disk(manifest: &InstallationManifest) -> Result<(), EncvolError> {
    let metadata = fs::metadata(&manifest.target_disk)
        .map_err(|_| EncvolError::UnsafeDisk("target disk does not exist".into()))?;
    if !metadata.file_type().is_block_device() {
        return Err(EncvolError::UnsafeDisk(
            "target is not a block device".into(),
        ));
    }
    let mounted = fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
        .collect::<Vec<_>>();
    if safety::is_mounted_source(&manifest.target_disk, &mounted) {
        return Err(EncvolError::UnsafeDisk(
            "target disk or its partition is mounted".into(),
        ));
    }
    Ok(())
}

fn cache_verified_rootfs(manifest: &InstallationManifest) -> Result<&'static Path, EncvolError> {
    // Use the initramfs root instead of /run: Debian mounts /run as a
    // separately capped tmpfs, which is too small for uncompressed tar images.
    let rootfs = Path::new("/encvol-rootfs.tar");
    let actual_rootfs_hash = bundle::download_to_path(&manifest.rootfs.archive_url, rootfs)?;
    if actual_rootfs_hash != manifest.rootfs.sha256.to_ascii_lowercase() {
        let _ = fs::remove_file(rootfs);
        return Err(EncvolError::Verification(
            "rootfs SHA-256 did not verify".into(),
        ));
    }
    Ok(rootfs)
}

fn create_mountpoints() -> Result<(), EncvolError> {
    fs::create_dir_all("/target")
        .map_err(|e| EncvolError::Unsupported(format!("cannot create target mountpoint: {e}")))?;
    Ok(())
}

fn create_layout(
    manifest: &InstallationManifest,
    firmware: Firmware,
    recovery_passphrase: &[u8],
) -> Result<(), EncvolError> {
    let commands = runtime_commands(manifest, firmware)?;
    for command in &commands {
        let input = if command[0] == "cryptsetup" {
            Some(recovery_passphrase)
        } else {
            None
        };
        run_command(command, input)?;
    }
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

fn bind_chroot_mounts() -> Result<(), EncvolError> {
    for (source, target) in [
        ("/dev", "/target/dev"),
        ("/proc", "/target/proc"),
        ("/sys", "/target/sys"),
    ] {
        fs::create_dir_all(target).map_err(|e| {
            EncvolError::Unsupported(format!("cannot create chroot mountpoint: {e}"))
        })?;
        run_command(
            &[
                "mount".into(),
                "--rbind".into(),
                source.into(),
                target.into(),
            ],
            None,
        )?;
    }
    Ok(())
}

fn install_target_packages(firmware: Firmware) -> Result<(), EncvolError> {
    run_command(
        &[
            "chroot".into(),
            "/target".into(),
            "apt-get".into(),
            "update".into(),
        ],
        None,
    )?;
    let mut install_command = vec![
        "chroot".into(),
        "/target".into(),
        "apt-get".into(),
        "install".into(),
        "-y".into(),
    ];
    install_command.extend(packages(firmware).iter().map(|package| (*package).into()));
    run_command(&install_command, None)
}

fn bind_tang_slot(
    manifest: &InstallationManifest,
    recovery_passphrase: &[u8],
) -> Result<(), EncvolError> {
    run_command(
        &[
            "clevis".into(),
            "luks".into(),
            "bind".into(),
            "-f".into(),
            "-k".into(),
            "-".into(),
            "-d".into(),
            partition(&manifest.target_disk, 2),
            "tang".into(),
            tang_config(manifest),
        ],
        Some(recovery_passphrase),
    )
}

fn install_bootloader(
    manifest: &InstallationManifest,
    firmware: Firmware,
) -> Result<(), EncvolError> {
    let grub_install = if firmware == Firmware::Uefi {
        vec![
            "chroot".into(),
            "/target".into(),
            "grub-install".into(),
            "--target=x86_64-efi".into(),
            "--efi-directory=/boot/efi".into(),
            "--bootloader-id=debian".into(),
            "--recheck".into(),
        ]
    } else {
        vec![
            "chroot".into(),
            "/target".into(),
            "grub-install".into(),
            manifest.target_disk.clone(),
        ]
    };
    run_command(&grub_install, None)?;
    run_command(
        &[
            "chroot".into(),
            "/target".into(),
            "update-initramfs".into(),
            "-u".into(),
            "-k".into(),
            "all".into(),
        ],
        None,
    )?;
    run_command(
        &["chroot".into(), "/target".into(), "update-grub".into()],
        None,
    )
}

/// Execute only from a RAM boot. The passphrase is supplied via stdin to
/// cryptsetup and never placed into a command, environment variable, ESP, or log.
#[allow(clippy::useless_vec)] // command arguments intentionally use owned String values
pub fn run(
    manifest: &InstallationManifest,
    options: &RuntimeOptions,
    recovery_passphrase: &[u8],
) -> Result<(), EncvolError> {
    safety::validate_disk_path(&manifest.target_disk)?;
    manifest.validate()?;
    verify_runtime_environment(options)?;
    if !options.execute {
        return Ok(());
    }

    verify_target_disk(manifest)?;
    let rootfs = cache_verified_rootfs(manifest)?;
    create_mountpoints()?;
    create_layout(manifest, options.firmware, recovery_passphrase)?;
    run_command(
        &extraction_command(manifest.rootfs.format, rootfs, Path::new("/target")),
        None,
    )?;
    prepare_target_runtime_directories(Path::new("/target"))?;
    write_root_configuration(manifest, options.firmware)?;
    bind_chroot_mounts()?;
    install_target_packages(options.firmware)?;
    bind_tang_slot(manifest, recovery_passphrase)?;
    install_bootloader(manifest, options.firmware)
}
