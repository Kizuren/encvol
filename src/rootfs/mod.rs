//! Building and validating portable Debian root filesystem archives.
//!
//! The descriptor is deliberately separate from the installation manifest: it
//! names a reusable artifact, while the manifest contains one host's disk,
//! network, and recovery configuration.
use crate::{bundle::sha256_hex, EncvolError};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;
use url::Url;

pub const ROOTFS_SCHEMA_VERSION: u32 = 1;
pub const REQUIRED_CAPABILITIES: [&str; 3] = ["systemd", "apt", "debian-package-compatibility"];
const RUNTIME_DIRECTORIES: [&str; 5] = ["dev", "proc", "sys", "run", "tmp"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveFormat {
    Tar,
    #[serde(rename = "tar.zst")]
    TarZst,
}

impl ArchiveFormat {
    pub fn parse(value: &str) -> Result<Self, EncvolError> {
        match value {
            "tar" => Ok(Self::Tar),
            "tar.zst" => Ok(Self::TarZst),
            _ => Err(EncvolError::Manifest(
                "rootfs archive format must be tar or tar.zst".into(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootfsDescriptor {
    pub schema_version: u32,
    #[serde(alias = "url")]
    pub archive_url: Url,
    pub sha256: String,
    pub release: String,
    pub architecture: String,
    pub provides: Vec<String>,
    pub format: ArchiveFormat,
}

impl RootfsDescriptor {
    pub fn validate(&self) -> Result<(), EncvolError> {
        if self.schema_version != ROOTFS_SCHEMA_VERSION {
            return Err(EncvolError::Manifest(format!(
                "only rootfs descriptor schema version {ROOTFS_SCHEMA_VERSION} is supported"
            )));
        }
        if self.archive_url.scheme() != "https" {
            return Err(EncvolError::Manifest(
                "rootfs archive URL must use HTTPS".into(),
            ));
        }
        if self.architecture != "amd64" {
            return Err(EncvolError::Manifest(
                "only amd64 rootfs archives are supported".into(),
            ));
        }
        if !valid_release(&self.release) {
            return Err(EncvolError::Manifest(
                "rootfs release must be a Debian codename".into(),
            ));
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(EncvolError::Manifest(
                "rootfs sha256 must be a 64-character hexadecimal digest".into(),
            ));
        }
        for capability in REQUIRED_CAPABILITIES {
            if !self.provides.iter().any(|item| item == capability) {
                return Err(EncvolError::Manifest(format!(
                    "rootfs must provide {capability}"
                )));
            }
        }
        Ok(())
    }
}

pub(crate) fn valid_release(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
}

fn rootfs_error(message: impl Into<String>) -> EncvolError {
    EncvolError::Unsupported(message.into())
}

/// `debootstrap` invocation used by `rootfs init`.
pub fn debootstrap_command(
    release: &str,
    root: &Path,
    mirror: Option<&Url>,
) -> Result<Vec<String>, EncvolError> {
    if !valid_release(release) {
        return Err(EncvolError::Manifest(
            "--release must be a Debian codename".into(),
        ));
    }
    let mut command = vec![
        "debootstrap".into(),
        "--arch=amd64".into(),
        "--include=apt,systemd-sysv".into(),
        release.into(),
        root.display().to_string(),
    ];
    if let Some(mirror) = mirror {
        if mirror.scheme() != "https" && mirror.scheme() != "http" {
            return Err(EncvolError::Manifest("mirror URL must use HTTP(S)".into()));
        }
        command.push(mirror.to_string());
    }
    Ok(command)
}

pub fn require_empty_workspace(root: &Path) -> Result<(), EncvolError> {
    if root.exists() {
        if !root.is_dir() {
            return Err(rootfs_error("rootfs workspace is not a directory"));
        }
        if fs::read_dir(root)
            .map_err(|e| rootfs_error(format!("cannot inspect rootfs workspace: {e}")))?
            .next()
            .is_some()
        {
            return Err(rootfs_error("rootfs workspace must be empty"));
        }
    } else {
        fs::create_dir_all(root)
            .map_err(|e| rootfs_error(format!("cannot create rootfs workspace: {e}")))?;
    }
    Ok(())
}

pub fn init_workspace(release: &str, root: &Path, mirror: Option<&Url>) -> Result<(), EncvolError> {
    require_empty_workspace(root)?;
    run_checked(&debootstrap_command(release, root, mirror)?)
}

pub fn validate_workspace(root: &Path) -> Result<(), EncvolError> {
    if !root.is_dir() {
        return Err(rootfs_error("rootfs workspace is not a directory"));
    }
    for required in [
        "usr/lib/systemd/systemd",
        "usr/bin/apt",
        "var/lib/dpkg/status",
    ] {
        if !root.join(required).is_file() {
            return Err(EncvolError::Manifest(format!(
                "rootfs workspace is missing required Debian component /{required}"
            )));
        }
    }
    Ok(())
}

/// Read the codename recorded by Debian's base-files package. This keeps a
/// descriptor tied to the workspace that was actually packaged.
pub fn workspace_release(root: &Path) -> Result<String, EncvolError> {
    let data = fs::read_to_string(root.join("etc/os-release"))
        .map_err(|e| rootfs_error(format!("cannot read Debian release metadata: {e}")))?;
    let release = data.lines().find_map(|line| {
        line.strip_prefix("VERSION_CODENAME=")
            .map(|value| value.trim_matches('"').to_owned())
    });
    let release = release.ok_or_else(|| {
        EncvolError::Manifest("rootfs workspace lacks VERSION_CODENAME in /etc/os-release".into())
    })?;
    if !valid_release(&release) {
        return Err(EncvolError::Manifest(
            "rootfs workspace has an invalid Debian release codename".into(),
        ));
    }
    Ok(release)
}

pub fn archive_exclusion_args() -> Vec<String> {
    RUNTIME_DIRECTORIES
        .iter()
        .map(|directory| format!("--exclude=./{directory}/*"))
        .collect()
}

/// GNU tar command that includes mountpoint directories while excluding their
/// transient contents. ACLs, xattrs, sparse extents, and numeric ownership are
/// retained so the archive can be extracted by the RAM installer without host
/// user/group lookups.
pub fn pack_command(root: &Path, output: &Path, format: ArchiveFormat) -> Vec<String> {
    let mut command = vec![
        "tar".into(),
        "--create".into(),
        "--file".into(),
        output.display().to_string(),
        "--numeric-owner".into(),
        "--acls".into(),
        "--xattrs".into(),
        "--sparse".into(),
    ];
    if format == ArchiveFormat::TarZst {
        command.push("--zstd".into());
    }
    command.extend(archive_exclusion_args());
    command.extend(["--directory".into(), root.display().to_string(), ".".into()]);
    command
}

pub fn extraction_command(format: ArchiveFormat, archive: &Path, target: &Path) -> Vec<String> {
    let mut command = vec!["tar".into()];
    if format == ArchiveFormat::TarZst {
        command.push("--zstd".into());
    }
    command.extend([
        "--numeric-owner".into(),
        "--acls".into(),
        "--xattrs".into(),
        "-xpf".into(),
        archive.display().to_string(),
        "-C".into(),
        target.display().to_string(),
    ]);
    command
}

pub fn descriptor_path(output: &Path) -> PathBuf {
    output.with_extension("json")
}

fn output_is_in_workspace(root: &Path, output: &Path) -> bool {
    let root = root.canonicalize().ok();
    let output = output
        .parent()
        .map(|parent| {
            if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            }
        })
        .and_then(|parent| parent.canonicalize().ok())
        .map(|parent| parent.join(output.file_name().unwrap_or_default()));
    matches!((root, output), (Some(root), Some(output)) if output.starts_with(&root))
}

pub fn pack_workspace(
    root: &Path,
    output: &Path,
    archive_url: Url,
    format: ArchiveFormat,
) -> Result<RootfsDescriptor, EncvolError> {
    validate_workspace(root)?;
    let release = workspace_release(root)?;
    if output_is_in_workspace(root, output) {
        return Err(rootfs_error(
            "rootfs archive output must not be inside the workspace",
        ));
    }
    if output.exists() {
        return Err(rootfs_error("rootfs archive output already exists"));
    }
    let descriptor_file = descriptor_path(output);
    if descriptor_file.exists() {
        return Err(rootfs_error("rootfs descriptor output already exists"));
    }
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| rootfs_error(format!("cannot create archive directory: {e}")))?;
    }
    run_checked(&pack_command(root, output, format))?;
    let archive = fs::read(output)
        .map_err(|e| rootfs_error(format!("cannot read created rootfs archive: {e}")))?;
    let descriptor = RootfsDescriptor {
        schema_version: ROOTFS_SCHEMA_VERSION,
        archive_url,
        sha256: sha256_hex(&archive),
        release,
        architecture: "amd64".into(),
        provides: REQUIRED_CAPABILITIES
            .iter()
            .map(|value| (*value).into())
            .collect(),
        format,
    };
    descriptor.validate()?;
    let data = serde_json::to_vec_pretty(&descriptor)
        .map_err(|e| rootfs_error(format!("cannot serialize rootfs descriptor: {e}")))?;
    fs::write(&descriptor_file, data)
        .map_err(|e| rootfs_error(format!("cannot write rootfs descriptor: {e}")))?;
    Ok(descriptor)
}

/// Conservative check for a source that is clearly a partition or a mapped
/// filesystem block device rather than a whole raw disk. The actual
/// block-device check happens immediately before it is mounted.
pub fn validate_import_source_path(source: &Path) -> Result<(), EncvolError> {
    if !source.is_absolute()
        || source
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || !(source.parent() == Some(Path::new("/dev"))
            || source.parent() == Some(Path::new("/dev/mapper")))
    {
        return Err(EncvolError::UnsafeDisk(
            "rootfs import source must be an absolute /dev/<partition> path".into(),
        ));
    }
    let name = source
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let partition = (name.starts_with("nvme") || name.starts_with("mmcblk"))
        && name
            .rsplit_once('p')
            .is_some_and(|(_, part)| !part.is_empty() && part.chars().all(char::is_numeric))
        || (name.starts_with("sd")
            || name.starts_with("vd")
            || name.starts_with("xvd")
            || name.starts_with("hd"))
            && name.chars().last().is_some_and(char::is_numeric);
    let mapped_device = source.parent() == Some(Path::new("/dev/mapper")) && !name.is_empty();
    if !partition && !mapped_device {
        return Err(EncvolError::UnsafeDisk(
            "rootfs import source must be a filesystem partition or mapped device, not a whole disk or image".into(),
        ));
    }
    Ok(())
}

pub fn readonly_mount_command(source: &Path, target: &Path) -> Vec<String> {
    vec![
        "mount".into(),
        "--read-only".into(),
        source.display().to_string(),
        target.display().to_string(),
    ]
}

pub fn import_source(
    source: &Path,
    output: &Path,
    archive_url: Url,
    format: ArchiveFormat,
) -> Result<RootfsDescriptor, EncvolError> {
    validate_import_source_path(source)?;
    let metadata = fs::metadata(source)
        .map_err(|e| rootfs_error(format!("cannot inspect import source: {e}")))?;
    if !std::os::unix::fs::FileTypeExt::is_block_device(&metadata.file_type()) {
        return Err(EncvolError::UnsafeDisk(
            "rootfs import source is not a block device".into(),
        ));
    }
    let mount =
        TempDir::new().map_err(|e| rootfs_error(format!("cannot create mountpoint: {e}")))?;
    run_checked(&readonly_mount_command(source, mount.path()))?;
    let result = pack_workspace(mount.path(), output, archive_url, format);
    let unmount = run_checked(&["umount".into(), mount.path().display().to_string()]);
    match (result, unmount) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(descriptor), Ok(())) => Ok(descriptor),
    }
}

fn run_checked(command: &[String]) -> Result<(), EncvolError> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| rootfs_error("empty rootfs command"))?;
    let status = Command::new(program)
        .args(arguments)
        .status()
        .map_err(|e| rootfs_error(format!("cannot run {program}: {e}")))?;
    if !status.success() {
        return Err(rootfs_error(format!("{program} failed with {status}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
