use crate::{manifest::InstallationManifest, EncvolError};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use super::{
    layout::{logical_volume, partition},
    Firmware,
};

pub(super) fn tang_config(manifest: &InstallationManifest) -> String {
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

pub(super) fn prepare_target_runtime_directories(root: &Path) -> Result<(), EncvolError> {
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

pub(super) fn write_root_configuration(
    manifest: &InstallationManifest,
    firmware: Firmware,
) -> Result<(), EncvolError> {
    write_root_configuration_at(Path::new("/target"), manifest, firmware)
}

pub(super) fn write_root_configuration_at(
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
