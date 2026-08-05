use crate::EncvolError;
use std::{
    fs,
    path::{Component, Path},
};

/// Refuse aliases, partitions, mapper paths, and relative paths.  A whole disk
/// is required because the installer replaces its partition table.
pub fn validate_disk_path(disk: &str) -> Result<(), EncvolError> {
    let path = Path::new(disk);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(EncvolError::UnsafeDisk(
            "disk must be an absolute /dev path".into(),
        ));
    }
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default();
    if path.parent() != Some(Path::new("/dev")) || name.is_empty() {
        return Err(EncvolError::UnsafeDisk(
            "only direct /dev/<disk> paths are accepted".into(),
        ));
    }
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(EncvolError::UnsafeDisk(
            "target must not be a /dev alias or symlink".into(),
        ));
    }
    // nvme0n1p1, vda1, and sda1 are partitions, while nvme0n1, vda, and sda are disks.
    let partition = (name.starts_with("nvme")
        && name.contains('p')
        && name
            .rsplit_once('p')
            .is_some_and(|(_, n)| n.chars().all(char::is_numeric)))
        || (name.starts_with("mmcblk")
            && name
                .rsplit_once('p')
                .is_some_and(|(_, n)| n.chars().all(char::is_numeric)))
        || ((name.starts_with("sd")
            || name.starts_with("vd")
            || name.starts_with("xvd")
            || name.starts_with("hd"))
            && name.chars().last().is_some_and(char::is_numeric));
    if partition
        || name.starts_with("mapper")
        || name.starts_with("loop")
        || name.starts_with("dm-")
    {
        return Err(EncvolError::UnsafeDisk(
            "target must be a whole physical disk, not a partition or virtual mapping".into(),
        ));
    }
    let alphabetic_disk = |prefix: &str| {
        name.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_lowercase())
        })
    };
    let direct_disk_name = alphabetic_disk("sd")
        || alphabetic_disk("vd")
        || alphabetic_disk("xvd")
        || alphabetic_disk("hd")
        || name.strip_prefix("nvme").is_some_and(|suffix| {
            suffix
                .split_once('n')
                .is_some_and(|(controller, namespace)| {
                    !controller.is_empty()
                        && !namespace.is_empty()
                        && controller.bytes().all(|byte| byte.is_ascii_digit())
                        && namespace.bytes().all(|byte| byte.is_ascii_digit())
                })
        })
        || name.strip_prefix("mmcblk").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        });
    if !direct_disk_name {
        return Err(EncvolError::UnsafeDisk(
            "target must use a supported direct whole-disk /dev name".into(),
        ));
    }
    Ok(())
}

pub fn require_confirmation(disk: &str, supplied: Option<&str>) -> Result<(), EncvolError> {
    let expected = format!("WIPE:{disk}");
    if supplied != Some(expected.as_str()) {
        return Err(EncvolError::UnsafeDisk(format!(
            "pass --confirm {expected} to authorize replacing this disk"
        )));
    }
    Ok(())
}

pub fn is_mounted_source(target: &str, mount_sources: &[String]) -> bool {
    mount_sources.iter().any(|source| {
        source == target
            || source
                .strip_prefix(target)
                .is_some_and(|suffix| partition_suffix(target, suffix))
    })
}

fn partition_suffix(target: &str, suffix: &str) -> bool {
    let Some(first) = suffix.bytes().next() else {
        return false;
    };
    let suffix = if target.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        let Some(suffix) = suffix.strip_prefix('p') else {
            return false;
        };
        suffix
    } else {
        if !first.is_ascii_digit() {
            return false;
        }
        suffix
    };
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_partitions_and_aliases() {
        for p in [
            "vda",
            "/dev/vda1",
            "/dev/nvme0n1p1",
            "/dev/mapper/a",
            "/dev/loop0",
            "/dev/root",
            "/dev/sda/../sdb",
            "/dev/mmcblk0p1",
        ] {
            assert!(validate_disk_path(p).is_err(), "{p}");
        }
        for p in ["/dev/vda", "/dev/sda", "/dev/nvme0n1"] {
            assert!(validate_disk_path(p).is_ok(), "{p}");
        }
    }
    #[test]
    fn confirmation_is_exact() {
        assert!(require_confirmation("/dev/vda", Some("WIPE:/dev/vda")).is_ok());
        assert!(require_confirmation("/dev/vda", Some("yes")).is_err());
    }

    #[test]
    fn mounted_source_matching_is_partition_aware() {
        assert!(is_mounted_source("/dev/vda", &["/dev/vda".into()]));
        assert!(is_mounted_source("/dev/vda", &["/dev/vda1".into()]));
        assert!(is_mounted_source(
            "/dev/nvme0n1",
            &["/dev/nvme0n1p2".into()]
        ));
        assert!(!is_mounted_source("/dev/vda", &["/dev/vdaa".into()]));
        assert!(!is_mounted_source(
            "/dev/nvme0n1",
            &["/dev/nvme0n10p1".into()]
        ));
        assert!(!is_mounted_source(
            "/dev/nvme0n1",
            &["/dev/nvme0n11".into()]
        ));
    }
}
