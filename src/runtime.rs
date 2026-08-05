//! The executable half of the RAM-resident installer.
//!
//! It is deliberately separate from client-side staging. `run()` only proceeds
//! when booted with `encvol.installer=1`, all validation succeeds, and the
//! caller supplies the same explicit disk acknowledgement used by the client.
use crate::{
    bundle, manifest::InstallationManifest, rootfs::extraction_command, safety, secrets::redact,
    EncvolError,
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firmware {
    Uefi,
    Bios,
}

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub firmware: Firmware,
    pub execute: bool,
    pub allow_non_ram: bool,
}

fn partition(disk: &str, number: u8) -> String {
    if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        format!("{disk}p{number}")
    } else {
        format!("{disk}{number}")
    }
}

fn logical_volume(name: &str) -> String {
    format!("/dev/mapper/encvol-{name}")
}

fn tang_config(manifest: &InstallationManifest) -> String {
    let url = manifest.tang_url.as_str().trim_end_matches('/');
    serde_json::json!({
        "url": url,
        "thp": manifest.tang_thumbprint,
    })
    .to_string()
}

fn enable_grub_cryptodisk(root: &Path) -> Result<(), EncvolError> {
    let path = root.join("etc/default/grub");
    let config = fs::read_to_string(&path).unwrap_or_default();
    let mut found = false;
    let mut lines = Vec::new();
    for line in config.lines() {
        if line.trim_start().starts_with("GRUB_ENABLE_CRYPTODISK=") {
            lines.push("GRUB_ENABLE_CRYPTODISK=y".to_string());
            found = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !found {
        lines.push("GRUB_ENABLE_CRYPTODISK=y".to_string());
    }
    fs::create_dir_all(root.join("etc/default")).map_err(|e| {
        EncvolError::Unsupported(format!("cannot create GRUB config directory: {e}"))
    })?;
    fs::write(path, format!("{}\n", lines.join("\n")))
        .map_err(|e| EncvolError::Unsupported(format!("cannot enable GRUB cryptodisk: {e}")))?;
    Ok(())
}

fn prepare_target_runtime_directories(root: &Path) -> Result<(), EncvolError> {
    for directory in ["tmp", "run", "var/tmp"] {
        fs::create_dir_all(root.join(directory)).map_err(|e| {
            EncvolError::Unsupported(format!("cannot create target /{directory}: {e}"))
        })?;
    }
    for directory in ["tmp", "var/tmp"] {
        fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o1777)).map_err(
            |e| EncvolError::Unsupported(format!("cannot set target /{directory} mode: {e}")),
        )?;
    }
    Ok(())
}

fn command_line_has_installer_flag() -> bool {
    fs::read_to_string("/proc/cmdline")
        .unwrap_or_default()
        .split_whitespace()
        .any(|v| v == "encvol.installer=1")
}
fn root_is_ram() -> bool {
    root_mount_is_ram(&fs::read_to_string("/proc/mounts").unwrap_or_default())
}

fn root_mount_is_ram(mounts: &str) -> bool {
    mounts.lines().any(|l| {
        let f: Vec<_> = l.split_whitespace().collect();
        f.len() > 2 && f[1] == "/" && matches!(f[2], "rootfs" | "tmpfs" | "ramfs")
    })
}

pub fn verify_runtime_environment(options: &RuntimeOptions) -> Result<(), EncvolError> {
    if !options.allow_non_ram && (!command_line_has_installer_flag() || !root_is_ram()) {
        return Err(EncvolError::UnsafeDisk(
            "installer must be booted from the signed RAM image with encvol.installer=1".into(),
        ));
    }
    Ok(())
}

pub fn runtime_commands(
    manifest: &InstallationManifest,
    firmware: Firmware,
) -> Result<Vec<Vec<String>>, EncvolError> {
    manifest.validate()?;
    let crypt = partition(&manifest.target_disk, 2);
    let mut c = Vec::new();
    c.push(vec![
        "wipefs".into(),
        "--all".into(),
        "--force".into(),
        manifest.target_disk.clone(),
    ]);
    c.push(vec![
        "sgdisk".into(),
        "--zap-all".into(),
        manifest.target_disk.clone(),
    ]);
    match firmware {
        Firmware::Uefi => c.push(vec![
            "sgdisk".into(),
            "--new=1:1MiB:+512MiB".into(),
            "--typecode=1:ef00".into(),
            "--new=2:0:0".into(),
            "--typecode=2:8309".into(),
            manifest.target_disk.clone(),
        ]),
        Firmware::Bios => c.push(vec![
            "sgdisk".into(),
            "--new=1:1MiB:+1MiB".into(),
            "--typecode=1:ef02".into(),
            "--new=2:0:0".into(),
            "--typecode=2:8309".into(),
            manifest.target_disk.clone(),
        ]),
    }
    c.extend([
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
                manifest.layout.as_ref().map(|x| x.swap_mib).unwrap_or(1024)
            ),
            "encvol".into(),
        ],
    ]);
    if manifest
        .layout
        .as_ref()
        .is_some_and(|layout| layout.data_volume)
    {
        c.push(vec![
            "lvcreate".into(),
            "--name".into(),
            "root".into(),
            "--extents".into(),
            "70%FREE".into(),
            "encvol".into(),
        ]);
        c.push(vec![
            "lvcreate".into(),
            "--name".into(),
            "data".into(),
            "--extents".into(),
            "100%FREE".into(),
            "encvol".into(),
        ]);
    } else {
        c.push(vec![
            "lvcreate".into(),
            "--name".into(),
            "root".into(),
            "--extents".into(),
            "100%FREE".into(),
            "encvol".into(),
        ]);
    }
    c.extend([
        vec!["mkfs.ext4".into(), "-F".into(), logical_volume("root")],
        vec!["mkswap".into(), logical_volume("swap")],
    ]);
    Ok(c)
}

fn run_command(command: &[String], stdin: Option<&[u8]>) -> Result<(), EncvolError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| EncvolError::Unsupported("empty installer command".into()))?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| EncvolError::Unsupported(format!("cannot run {program}: {e}")))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| EncvolError::Unsupported("cannot provide command input".into()))?
            .write_all(input)
            .map_err(|e| {
                EncvolError::Unsupported(format!("cannot provide installer input: {e}"))
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| EncvolError::Unsupported(format!("cannot wait for {program}: {e}")))?;
    if !output.status.success() {
        return Err(EncvolError::Unsupported(format!(
            "{program} failed: {}",
            redact(&String::from_utf8_lossy(&output.stderr))
        )));
    }
    Ok(())
}

fn write_root_configuration(
    manifest: &InstallationManifest,
    firmware: Firmware,
) -> Result<(), EncvolError> {
    write_root_configuration_at(Path::new("/target"), manifest, firmware)
}

fn write_root_configuration_at(
    root: &Path,
    manifest: &InstallationManifest,
    firmware: Firmware,
) -> Result<(), EncvolError> {
    fs::create_dir_all(root.join("etc/systemd/network")).map_err(|e| {
        EncvolError::Unsupported(format!("cannot create target configuration: {e}"))
    })?;
    fs::write(
        root.join("etc/systemd/network/10-encvol.network"),
        manifest.network.to_networkd(),
    )
    .map_err(|e| EncvolError::Unsupported(format!("cannot write network configuration: {e}")))?;
    let crypt = partition(&manifest.target_disk, 2);
    fs::write(
        root.join("etc/crypttab"),
        format!("encvol_crypt {crypt} none luks,discard\n"),
    )
    .map_err(|e| EncvolError::Unsupported(format!("cannot write crypttab: {e}")))?;
    let mut fstab = format!(
        "{} / ext4 defaults 0 1\n{} none swap sw 0 0\n",
        logical_volume("root"),
        logical_volume("swap")
    );
    if manifest
        .layout
        .as_ref()
        .is_some_and(|layout| layout.data_volume)
    {
        fstab.push_str(&format!(
            "{} /data ext4 defaults 0 2\n",
            logical_volume("data")
        ));
    }
    fs::write(root.join("etc/fstab"), fstab)
        .map_err(|e| EncvolError::Unsupported(format!("cannot write fstab: {e}")))?;
    fs::create_dir_all(root.join("etc/dropbear/initramfs")).map_err(|e| {
        EncvolError::Unsupported(format!("cannot create recovery SSH configuration: {e}"))
    })?;
    let recovery_key = format!(
        "command=\"/usr/local/sbin/encvol-recovery-unlock\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty {}\n",
        manifest.recovery_authorized_key.trim()
    );
    fs::write(
        root.join("etc/dropbear/initramfs/authorized_keys"),
        recovery_key,
    )
    .map_err(|e| EncvolError::Unsupported(format!("cannot write recovery SSH key: {e}")))?;
    fs::write(
        root.join("etc/dropbear/initramfs/dropbear.conf"),
        "DROPBEAR_OPTIONS=\"-s -j -k -p 2222\"\n",
    )
    .map_err(|e| {
        EncvolError::Unsupported(format!("cannot write recovery SSH restrictions: {e}"))
    })?;
    fs::create_dir_all(root.join("etc/initramfs-tools/hooks")).map_err(|e| {
        EncvolError::Unsupported(format!("cannot create initramfs hook directory: {e}"))
    })?;
    fs::write(
        root.join("usr/local/sbin/encvol-recovery-unlock"),
        format!(
            "#!/bin/sh\nset -eu\nIFS= read -r passphrase\nprintf '%s' \"$passphrase\" | cryptsetup open --key-file=- {crypt} encvol_crypt\nkillall dropbear 2>/dev/null || true\n"
        ),
    )
    .map_err(|e| EncvolError::Unsupported(format!("cannot write recovery unlock helper: {e}")))?;
    fs::set_permissions(
        root.join("usr/local/sbin/encvol-recovery-unlock"),
        fs::Permissions::from_mode(0o700),
    )
    .map_err(|e| EncvolError::Unsupported(format!("cannot secure recovery unlock helper: {e}")))?;
    fs::write(
        root.join("etc/initramfs-tools/hooks/encvol-recovery"),
        "#!/bin/sh\nset -eu\nPREREQ=''\nprereqs() { echo \"$PREREQ\"; }\ncase \"${1:-}\" in prereqs) prereqs; exit 0;; esac\n. /usr/share/initramfs-tools/hook-functions\ncopy_exec /usr/local/sbin/encvol-recovery-unlock\n",
    )
    .map_err(|e| EncvolError::Unsupported(format!("cannot write recovery initramfs hook: {e}")))?;
    fs::set_permissions(
        root.join("etc/initramfs-tools/hooks/encvol-recovery"),
        fs::Permissions::from_mode(0o755),
    )
    .map_err(|e| EncvolError::Unsupported(format!("cannot enable recovery initramfs hook: {e}")))?;
    if firmware == Firmware::Uefi {
        fs::create_dir_all(root.join("boot/efi"))
            .map_err(|e| EncvolError::Unsupported(format!("cannot prepare ESP: {e}")))?;
    }
    enable_grub_cryptodisk(root)?;
    Ok(())
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
    // Cache and verify the rootfs before the first destructive command.  Use
    // the initramfs root instead of /run: Debian mounts /run as a separately
    // capped tmpfs, which is too small for uncompressed tar rootfs images.
    let rootfs = Path::new("/encvol-rootfs.tar");
    let actual_rootfs_hash = bundle::download_to_path(&manifest.rootfs.archive_url, rootfs)?;
    if actual_rootfs_hash != manifest.rootfs.sha256.to_ascii_lowercase() {
        let _ = fs::remove_file(rootfs);
        return Err(EncvolError::Verification(
            "rootfs SHA-256 did not verify".into(),
        ));
    }
    fs::create_dir_all("/target")
        .map_err(|e| EncvolError::Unsupported(format!("cannot create target mountpoint: {e}")))?;
    let commands = runtime_commands(manifest, options.firmware)?;
    for command in &commands {
        let input = if command[0] == "cryptsetup" {
            Some(recovery_passphrase)
        } else {
            None
        };
        run_command(command, input)?;
    }
    run_command(
        &vec!["mount".into(), logical_volume("root"), "/target".into()],
        None,
    )?;
    if manifest
        .layout
        .as_ref()
        .is_some_and(|layout| layout.data_volume)
    {
        run_command(
            &vec!["mkfs.ext4".into(), "-F".into(), logical_volume("data")],
            None,
        )?;
        fs::create_dir_all("/target/data")
            .map_err(|e| EncvolError::Unsupported(format!("cannot create data mountpoint: {e}")))?;
        run_command(
            &vec![
                "mount".into(),
                logical_volume("data"),
                "/target/data".into(),
            ],
            None,
        )?;
    }
    if options.firmware == Firmware::Uefi {
        fs::create_dir_all("/target/boot/efi")
            .map_err(|e| EncvolError::Unsupported(format!("cannot create ESP mountpoint: {e}")))?;
        run_command(
            &vec![
                "mkfs.fat".into(),
                "-F32".into(),
                partition(&manifest.target_disk, 1),
            ],
            None,
        )?;
        run_command(
            &vec![
                "mount".into(),
                partition(&manifest.target_disk, 1),
                "/target/boot/efi".into(),
            ],
            None,
        )?;
    }
    run_command(
        &extraction_command(manifest.rootfs.format, rootfs, Path::new("/target")),
        None,
    )?;
    prepare_target_runtime_directories(Path::new("/target"))?;
    write_root_configuration(manifest, options.firmware)?;
    for (source, target) in [
        ("/dev", "/target/dev"),
        ("/proc", "/target/proc"),
        ("/sys", "/target/sys"),
    ] {
        fs::create_dir_all(target).map_err(|e| {
            EncvolError::Unsupported(format!("cannot create chroot mountpoint: {e}"))
        })?;
        run_command(
            &vec![
                "mount".into(),
                "--rbind".into(),
                source.into(),
                target.into(),
            ],
            None,
        )?;
    }
    let packages = if options.firmware == Firmware::Uefi {
        [
            "linux-image-amd64",
            "grub-efi-amd64",
            "shim-signed",
            "cryptsetup",
            "lvm2",
            "clevis",
            "clevis-luks",
            "clevis-initramfs",
            "dropbear-initramfs",
        ]
        .as_slice()
    } else {
        [
            "linux-image-amd64",
            "grub-pc",
            "cryptsetup",
            "lvm2",
            "clevis",
            "clevis-luks",
            "clevis-initramfs",
            "dropbear-initramfs",
        ]
        .as_slice()
    };
    run_command(
        &vec![
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
    install_command.extend(packages.iter().map(|package| (*package).into()));
    run_command(&install_command, None)?;
    let tang = tang_config(manifest);
    run_command(
        &vec![
            "clevis".into(),
            "luks".into(),
            "bind".into(),
            "-f".into(),
            "-k".into(),
            "-".into(),
            "-d".into(),
            partition(&manifest.target_disk, 2),
            "tang".into(),
            tang,
        ],
        Some(recovery_passphrase),
    )?;
    let grub_install = if options.firmware == Firmware::Uefi {
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
        &vec![
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
        &vec!["chroot".into(), "/target".into(), "update-grub".into()],
        None,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{manifest::*, network::*};
    use url::Url;
    fn m() -> InstallationManifest {
        InstallationManifest {
            schema_version: 1,
            target_disk: "/dev/nvme0n1".into(),
            rootfs: crate::rootfs::RootfsDescriptor {
                schema_version: 1,
                archive_url: Url::parse("https://x/root").unwrap(),
                sha256: "a".repeat(64),
                release: "bookworm".into(),
                architecture: "amd64".into(),
                provides: vec![
                    "systemd".into(),
                    "apt".into(),
                    "debian-package-compatibility".into(),
                ],
                format: crate::rootfs::ArchiveFormat::Tar,
            },
            tang_url: Url::parse("https://tang/x").unwrap(),
            tang_thumbprint: "pin".into(),
            recovery_authorized_key: "ssh-ed25519 AAA".into(),
            network: NetworkConfig {
                interface: "eth0".into(),
                mac_address: None,
                mode: NetworkMode::Dhcp,
                addresses: vec![],
                gateway: None,
                dns: vec![],
            },
            layout: None,
        }
    }
    #[test]
    fn uefi_layout_uses_esp_and_luks() {
        let c = runtime_commands(&m(), Firmware::Uefi).unwrap();
        assert!(c[2].iter().any(|v| v.contains("ef00")));
        assert!(c.iter().flatten().any(|v| v == "/dev/nvme0n1p2"));
    }
    #[test]
    fn dry_run_does_not_need_ram_environment() {
        let o = RuntimeOptions {
            firmware: Firmware::Bios,
            execute: false,
            allow_non_ram: true,
        };
        assert!(run(&m(), &o, b"x").is_ok());
    }

    #[test]
    fn initramfs_rootfs_counts_as_ram_root() {
        assert!(root_mount_is_ram(
            "rootfs / rootfs rw 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        ));
        assert!(root_mount_is_ram("tmpfs / tmpfs rw,size=1024k 0 0\n"));
        assert!(!root_mount_is_ram("/dev/vda1 / ext4 rw,relatime 0 0\n"));
    }

    #[test]
    fn tang_config_uses_normalized_base_url() {
        let mut manifest = m();
        manifest.tang_url = Url::parse("http://192.168.231.1:8080").unwrap();
        assert_eq!(
            tang_config(&manifest),
            r#"{"thp":"pin","url":"http://192.168.231.1:8080"}"#
        );
    }

    #[test]
    fn target_runtime_directories_support_chroot_package_scripts() {
        let dir = tempfile::tempdir().unwrap();
        prepare_target_runtime_directories(dir.path()).unwrap();

        for directory in ["tmp", "run", "var/tmp"] {
            assert!(dir.path().join(directory).is_dir());
        }
        for directory in ["tmp", "var/tmp"] {
            assert_eq!(
                std::fs::metadata(dir.path().join(directory))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o1777
            );
        }
    }

    #[test]
    fn target_configuration_is_restricted_and_firmware_aware() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("usr/local/sbin")).unwrap();
        write_root_configuration_at(dir.path(), &m(), Firmware::Uefi).unwrap();

        let network =
            std::fs::read_to_string(dir.path().join("etc/systemd/network/10-encvol.network"))
                .unwrap();
        assert!(network.contains("DHCP=yes"));
        assert!(dir.path().join("boot/efi").is_dir());
        let grub = std::fs::read_to_string(dir.path().join("etc/default/grub")).unwrap();
        assert!(grub.contains("GRUB_ENABLE_CRYPTODISK=y\n"));

        let authorized =
            std::fs::read_to_string(dir.path().join("etc/dropbear/initramfs/authorized_keys"))
                .unwrap();
        assert!(authorized.starts_with("command=\"/usr/local/sbin/encvol-recovery-unlock\""));
        assert!(authorized.contains("no-port-forwarding"));
        assert!(authorized.contains("no-pty"));

        let helper = dir.path().join("usr/local/sbin/encvol-recovery-unlock");
        let helper_text = std::fs::read_to_string(&helper).unwrap();
        assert!(helper_text.contains("cryptsetup open --key-file=- /dev/nvme0n1p2"));
        assert_eq!(
            std::fs::metadata(helper).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let hook =
            std::fs::read_to_string(dir.path().join("etc/initramfs-tools/hooks/encvol-recovery"))
                .unwrap();
        assert!(hook.contains("case \"${1:-}\" in prereqs)"));
    }
}
