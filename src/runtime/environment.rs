use crate::EncvolError;
use std::fs;

use super::RuntimeOptions;

fn command_line_has_installer_flag() -> bool {
    fs::read_to_string("/proc/cmdline")
        .unwrap_or_default()
        .split_whitespace()
        .any(|v| v == "encvol.installer=1")
}

fn root_is_ram() -> bool {
    root_mount_is_ram(&fs::read_to_string("/proc/mounts").unwrap_or_default())
}

pub(super) fn root_mount_is_ram(mounts: &str) -> bool {
    mounts.lines().any(|l| {
        let f: Vec<_> = l.split_whitespace().collect();
        f.len() > 2 && f[1] == "/" && matches!(f[2], "rootfs" | "tmpfs" | "ramfs")
    })
}

pub(super) fn verify_runtime_environment(options: &RuntimeOptions) -> Result<(), EncvolError> {
    if !options.allow_non_ram && (!command_line_has_installer_flag() || !root_is_ram()) {
        return Err(EncvolError::UnsafeDisk(
            "installer must be booted from the signed RAM image with encvol.installer=1".into(),
        ));
    }
    Ok(())
}
