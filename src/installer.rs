//! RAM-installer operations expressed as a reviewable sequence.
use crate::{
    bundle::SignatureVerification,
    handoff::Handoff,
    manifest::{InstallationManifest, Layout},
    EncvolError,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct InstallerPlan {
    pub target_disk: String,
    pub firmware: String,
    pub signature_verification: String,
    pub steps: Vec<String>,
}

pub fn build_plan(
    manifest: &InstallationManifest,
    handoff: Handoff,
) -> Result<InstallerPlan, EncvolError> {
    build_plan_with_signature_verification(manifest, handoff, SignatureVerification::Verified)
}

pub fn build_plan_with_signature_verification(
    manifest: &InstallationManifest,
    handoff: Handoff,
    signature_verification: SignatureVerification,
) -> Result<InstallerPlan, EncvolError> {
    manifest.validate()?;
    if handoff == Handoff::Unsupported {
        return Err(EncvolError::Unsupported(
            "cannot create an installer plan without a supported handoff".into(),
        ));
    }
    let layout = manifest.layout.clone().unwrap_or(Layout {
        swap_mib: 1024,
        data_volume: false,
    });
    let firmware = if handoff == Handoff::UefiBootnext {
        "uefi"
    } else {
        "bios-or-uefi"
    };
    let mut steps=vec![
        "reverify installer signature, manifest, target disk, and rootfs SHA-256 in RAM".into(),
        format!("wipe partition table on {} only after revalidation", manifest.target_disk),
        if firmware=="uefi" { "create EFI System Partition and LUKS2 partition".into() } else { "create BIOS boot partition and LUKS2 partition (UEFI boots use ESP when selected)".into() },
        "create LUKS2 -> LVM -> ext4 root and swap volumes using remaining capacity".into(),
        format!("create {} MiB swap logical volume", layout.swap_mib),
        "verify then extract Debian-compatible rootfs; configure kernel, GRUB, initramfs, LVM, crypttab and systemd-networkd".into(),
        "bind the LUKS slot to Tang using pinned trust material; retain recovery passphrase without placing a volume key on ESP".into(),
        "install restricted initramfs SSH recovery that accepts only the supplied public key and exits after unlock".into(),
    ];
    if layout.data_volume {
        steps.push("allocate remaining free extents to a growable data logical volume".into());
    }
    Ok(InstallerPlan {
        target_disk: manifest.target_disk.clone(),
        firmware: firmware.into(),
        signature_verification: signature_verification.as_str().into(),
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use crate::network::*;
    use url::Url;
    fn m() -> InstallationManifest {
        InstallationManifest {
            schema_version: 1,
            target_disk: "/dev/vda".into(),
            rootfs: crate::rootfs::RootfsDescriptor {
                schema_version: 1,
                archive_url: Url::parse("https://x/a").unwrap(),
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
            tang_url: Url::parse("https://t/a").unwrap(),
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
    fn keeps_key_off_esp() {
        let p = build_plan(&m(), Handoff::Kexec).unwrap();
        assert!(p
            .steps
            .join(" ")
            .contains("without placing a volume key on ESP"));
    }

    #[test]
    fn records_explicit_unsigned_policy_in_review_plan() {
        let plan = build_plan_with_signature_verification(
            &m(),
            Handoff::Kexec,
            SignatureVerification::Disabled,
        )
        .unwrap();
        assert_eq!(plan.signature_verification, "disabled");
    }
}
