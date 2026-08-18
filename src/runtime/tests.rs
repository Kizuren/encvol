use super::*;
use crate::{manifest::*, network::*};
use std::os::unix::fs::PermissionsExt;
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
        std::fs::read_to_string(dir.path().join("etc/systemd/network/10-encvol.network")).unwrap();
    assert!(network.contains("DHCP=yes"));
    assert!(dir.path().join("boot/efi").is_dir());
    let grub = std::fs::read_to_string(dir.path().join("etc/default/grub")).unwrap();
    assert!(grub.contains("GRUB_ENABLE_CRYPTODISK=y\n"));

    let authorized =
        std::fs::read_to_string(dir.path().join("etc/dropbear/initramfs/authorized_keys")).unwrap();
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
