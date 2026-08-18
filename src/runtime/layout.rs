use crate::{manifest::InstallationManifest, EncvolError};

use super::Firmware;

pub(super) fn partition(disk: &str, number: u8) -> String {
    if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        format!("{disk}p{number}")
    } else {
        format!("{disk}{number}")
    }
}

pub(super) fn logical_volume(name: &str) -> String {
    format!("/dev/mapper/encvol-{name}")
}

pub(super) fn runtime_commands(
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
