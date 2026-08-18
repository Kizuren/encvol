use std::path::{Path, PathBuf};

pub fn bundle_path(directory: &Path, version: &str) -> PathBuf {
    directory.join(format!("encvol-installer-{version}.bundle"))
}

pub fn signature_path(directory: &Path, version: &str) -> PathBuf {
    directory.join(format!("encvol-installer-{version}.bundle.sig"))
}

pub fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && !version.contains("..")
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
