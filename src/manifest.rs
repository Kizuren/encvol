use crate::{network::NetworkConfig, rootfs::RootfsDescriptor, safety, EncvolError};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layout {
    #[serde(default = "default_swap")]
    pub swap_mib: u64,
    #[serde(default)]
    pub data_volume: bool,
}
fn default_swap() -> u64 {
    1024
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationManifest {
    pub schema_version: u32,
    pub target_disk: String,
    pub rootfs: RootfsDescriptor,
    pub tang_url: Url,
    pub tang_thumbprint: String,
    pub recovery_authorized_key: String,
    pub network: NetworkConfig,
    #[serde(default)]
    pub layout: Option<Layout>,
}

impl InstallationManifest {
    pub fn validate(&self) -> Result<(), EncvolError> {
        if self.schema_version != 1 {
            return Err(EncvolError::Manifest(
                "only schema version 1 is supported".into(),
            ));
        }
        safety::validate_disk_path(&self.target_disk)?;
        self.rootfs.validate()?;
        if (self.tang_url.scheme() != "https" && self.tang_url.scheme() != "http")
            || self.tang_url.host_str().is_none()
            || !self.tang_url.username().is_empty()
            || self.tang_url.password().is_some()
        {
            return Err(EncvolError::Manifest("Tang URL must use HTTP(S)".into()));
        }
        if self.tang_thumbprint.trim().is_empty() {
            return Err(EncvolError::Manifest(
                "Tang thumbprint is required (TOFU is not allowed)".into(),
            ));
        }
        if self.recovery_authorized_key.contains(['\n', '\r'])
            || !self.recovery_authorized_key.starts_with("ssh-")
            || self.recovery_authorized_key.split_whitespace().count() < 2
        {
            return Err(EncvolError::Manifest(
                "recovery key must be one OpenSSH public-key line".into(),
            ));
        }
        self.network.validate()?;
        if let Some(layout) = &self.layout {
            if layout.swap_mib == 0 {
                return Err(EncvolError::Manifest("swap size must be non-zero".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{NetworkConfig, NetworkMode};
    fn manifest() -> InstallationManifest {
        InstallationManifest {
            schema_version: 1,
            target_disk: "/dev/vda".into(),
            rootfs: RootfsDescriptor {
                schema_version: 1,
                archive_url: Url::parse("https://x/rootfs.tar").unwrap(),
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
            tang_thumbprint: "abc".into(),
            recovery_authorized_key: "ssh-ed25519 AAAA test".into(),
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
    fn validates() {
        assert!(manifest().validate().is_ok());
    }
    #[test]
    fn requires_debian_compat() {
        let mut m = manifest();
        m.rootfs.provides.clear();
        assert!(m.validate().is_err());
    }
    #[test]
    fn rejects_multiple_recovery_key_lines() {
        let mut m = manifest();
        m.recovery_authorized_key.push_str("\nssh-ed25519 injected");
        assert!(m.validate().is_err());
    }
}
