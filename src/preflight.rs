use crate::{
    handoff::{select_handoff, Handoff, HostCapabilities},
    network::{NetworkConfig, NetworkMode},
    safety, EncvolError,
};
use serde::Serialize;
use std::{
    fs,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Serialize)]
pub struct PreflightReport {
    pub target_disk: String,
    pub handoff: Handoff,
    pub capabilities: HostCapabilities,
    pub network: Option<NetworkConfig>,
    pub warnings: Vec<String>,
}

fn program_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|p| p.join(name).is_file()))
}
fn kexec_load_enabled() -> bool {
    [
        "/proc/sys/kernel/kexec_load_disabled",
        "/sys/kernel/kexec_load_disabled",
    ]
    .iter()
    .find_map(|path| fs::read_to_string(path).ok())
    .is_some_and(|value| value.trim() != "1")
}
fn mounted_sources() -> Vec<String> {
    fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .collect()
}
fn mounted_esp() -> Option<PathBuf> {
    fs::read_to_string("/proc/mounts")
        .ok()?
        .lines()
        .find_map(|line| {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() >= 3 && (f[2] == "vfat" || f[2] == "fat" || f[2] == "msdos") {
                let p = PathBuf::from(f[1]);
                if p.is_dir() && !fs::metadata(&p).ok()?.permissions().readonly() {
                    Some(p)
                } else {
                    None
                }
            } else {
                None
            }
        })
}
fn default_route_interface() -> Option<String> {
    let o = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&o.stdout);
    let words: Vec<_> = s.split_whitespace().collect();
    words.windows(2).find_map(|w| {
        if w[0] == "dev" {
            Some(w[1].to_owned())
        } else {
            None
        }
    })
}
fn dns() -> Vec<String> {
    fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            l.strip_prefix("nameserver ")
                .map(str::trim)
                .map(str::to_owned)
        })
        .collect()
}
fn host_network() -> Option<NetworkConfig> {
    let interface = default_route_interface()?;
    let link = fs::read_to_string(format!("/sys/class/net/{interface}/address"))
        .ok()
        .map(|x| x.trim().to_owned());
    // Preserving DHCP avoids accidentally pinning a transient lease. Static
    // conversion is accepted through the versioned manifest schema.
    Some(NetworkConfig {
        interface,
        mac_address: link,
        mode: NetworkMode::Dhcp,
        addresses: vec![],
        gateway: None,
        dns: dns(),
    })
}
pub fn probe(disk: &str) -> Result<PreflightReport, EncvolError> {
    safety::validate_disk_path(disk)?;
    let metadata =
        fs::metadata(disk).map_err(|_| EncvolError::UnsafeDisk("target does not exist".into()))?;
    if !metadata.file_type().is_block_device() {
        return Err(EncvolError::UnsafeDisk(
            "target is not a block device".into(),
        ));
    }
    if safety::is_mounted_source(disk, &mounted_sources()) {
        return Err(EncvolError::UnsafeDisk(
            "target or one of its partitions is mounted".into(),
        ));
    }
    let uefi = Path::new("/sys/firmware/efi").is_dir();
    let cap = HostCapabilities {
        kexec: program_exists("kexec") && kexec_load_enabled(),
        uefi,
        writable_esp: if uefi { mounted_esp() } else { None },
        efi_variables: Path::new("/sys/firmware/efi/efivars").is_dir(),
        grub: program_exists("grub-reboot") && Path::new("/boot/grub/grub.cfg").is_file(),
    };
    let handoff = select_handoff(&cap);
    let mut warnings = Vec::new();
    if handoff == Handoff::Unsupported {
        warnings.push("no safe installer handoff is available; no writes will be made".into());
    }
    if host_network().is_none() {
        warnings.push("could not determine active network interface".into());
    }
    Ok(PreflightReport {
        target_disk: disk.into(),
        handoff,
        capabilities: cap,
        network: host_network(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_target_is_rejected() {
        assert!(probe("/dev/encvol-does-not-exist").is_err());
    }
    #[test]
    fn non_block_target_is_rejected() {
        assert!(probe("/dev/null").is_err());
    }
}
