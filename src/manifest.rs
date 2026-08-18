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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SelfInstallSource {
    HttpsRootfs {
        rootfs: RootfsDescriptor,
    },
    LiveRoot {
        #[serde(default = "default_live_root_format")]
        format: crate::rootfs::ArchiveFormat,
        release: String,
    },
}

fn default_live_root_format() -> crate::rootfs::ArchiveFormat {
    crate::rootfs::ArchiveFormat::TarZst
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootPartitionIdentity {
    pub path: String,
    pub partition_number: u32,
    pub uuid: Option<String>,
    pub fstype: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum StagingStrategy {
    ExistingFree {
        staging_partition_number: u32,
        staging_size_mib: u64,
    },
    ShrinkExt4 {
        staging_partition_number: u32,
        root_target_size_mib: u64,
        root_partition_end_mib: u64,
        staging_size_mib: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfInstallManifest {
    pub schema_version: u32,
    pub mode: String,
    pub target_disk: String,
    pub source: SelfInstallSource,
    pub original_root: RootPartitionIdentity,
    pub staging: StagingStrategy,
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

impl SelfInstallManifest {
    pub fn validate(&self) -> Result<(), EncvolError> {
        if self.schema_version != 1 {
            return Err(EncvolError::Manifest(
                "only schema version 1 is supported".into(),
            ));
        }
        if self.mode != "self-install" {
            return Err(EncvolError::Manifest(
                "self-install manifest mode must be self-install".into(),
            ));
        }
        safety::validate_disk_path(&self.target_disk)?;
        if self.original_root.path == self.target_disk
            || !safety::is_mounted_source(
                &self.target_disk,
                std::slice::from_ref(&self.original_root.path),
            )
            || self.original_root.partition_number == 0
            || self.original_root.fstype.trim().is_empty()
        {
            return Err(EncvolError::Manifest(
                "original root partition identity is invalid".into(),
            ));
        }
        match &self.source {
            SelfInstallSource::HttpsRootfs { rootfs } => rootfs.validate()?,
            SelfInstallSource::LiveRoot { release, .. } => {
                if !crate::rootfs::valid_release(release) {
                    return Err(EncvolError::Manifest(
                        "live root release must be a Debian codename".into(),
                    ));
                }
            }
        }
        match &self.staging {
            StagingStrategy::ExistingFree {
                staging_partition_number,
                staging_size_mib,
            }
            | StagingStrategy::ShrinkExt4 {
                staging_partition_number,
                staging_size_mib,
                ..
            } => {
                if *staging_partition_number == 0 || *staging_size_mib == 0 {
                    return Err(EncvolError::Manifest(
                        "staging partition number and size are required".into(),
                    ));
                }
            }
        }
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

    pub fn installation_manifest(&self, rootfs: RootfsDescriptor) -> InstallationManifest {
        InstallationManifest {
            schema_version: self.schema_version,
            target_disk: self.target_disk.clone(),
            rootfs,
            tang_url: self.tang_url.clone(),
            tang_thumbprint: self.tang_thumbprint.clone(),
            recovery_authorized_key: self.recovery_authorized_key.clone(),
            network: self.network.clone(),
            layout: self.layout.clone(),
        }
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
    fn self_install_manifest_validates() {
        let base = manifest();
        let m = SelfInstallManifest {
            schema_version: 1,
            mode: "self-install".into(),
            target_disk: "/dev/vda".into(),
            source: SelfInstallSource::LiveRoot {
                format: crate::rootfs::ArchiveFormat::TarZst,
                release: "bookworm".into(),
            },
            original_root: RootPartitionIdentity {
                path: "/dev/vda1".into(),
                partition_number: 1,
                uuid: Some("root-uuid".into()),
                fstype: "ext4".into(),
            },
            staging: StagingStrategy::ShrinkExt4 {
                staging_partition_number: 3,
                root_target_size_mib: 4096,
                root_partition_end_mib: 4097,
                staging_size_mib: 2048,
            },
            tang_url: base.tang_url,
            tang_thumbprint: base.tang_thumbprint,
            recovery_authorized_key: base.recovery_authorized_key,
            network: base.network,
            layout: Some(Layout {
                swap_mib: 1024,
                data_volume: false,
            }),
        };
        assert!(m.validate().is_ok());
        let install = m.installation_manifest(crate::rootfs::RootfsDescriptor {
            schema_version: 1,
            archive_url: Url::parse("https://self-install.invalid/root.tar.zst").unwrap(),
            sha256: "b".repeat(64),
            release: "bookworm".into(),
            architecture: "amd64".into(),
            provides: vec![
                "systemd".into(),
                "apt".into(),
                "debian-package-compatibility".into(),
            ],
            format: crate::rootfs::ArchiveFormat::TarZst,
        });
        assert_eq!(install.target_disk, "/dev/vda");
        assert_eq!(install.layout.unwrap().swap_mib, 1024);
    }
    #[test]
    fn self_install_manifest_rejects_partition_prefix_collision() {
        let base = manifest();
        let m = SelfInstallManifest {
            schema_version: 1,
            mode: "self-install".into(),
            target_disk: "/dev/vda".into(),
            source: SelfInstallSource::LiveRoot {
                format: crate::rootfs::ArchiveFormat::TarZst,
                release: "bookworm".into(),
            },
            original_root: RootPartitionIdentity {
                path: "/dev/vdaa1".into(),
                partition_number: 1,
                uuid: None,
                fstype: "ext4".into(),
            },
            staging: StagingStrategy::ExistingFree {
                staging_partition_number: 3,
                staging_size_mib: 2048,
            },
            tang_url: base.tang_url,
            tang_thumbprint: base.tang_thumbprint,
            recovery_authorized_key: base.recovery_authorized_key,
            network: base.network,
            layout: None,
        };
        assert!(m.validate().is_err());
    }
    #[test]
    fn rejects_multiple_recovery_key_lines() {
        let mut m = manifest();
        m.recovery_authorized_key.push_str("\nssh-ed25519 injected");
        assert!(m.validate().is_err());
    }
}
