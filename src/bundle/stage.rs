use crate::{
    bundle::{read_verified_bundle, VerificationPolicy},
    EncvolError,
};
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

pub(crate) const MAX_COMPONENT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct StagedBundle {
    pub directory: PathBuf,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub uki: Option<PathBuf>,
}

/// Extract only the three defined artifact paths, after the requested bundle
/// verification. `tar` is parsed directly so path traversal and symlinks are
/// rejected.
pub fn stage_bundle(
    bundle: &Path,
    signature: &Path,
    public_key_hex: &str,
    destination: &Path,
) -> Result<StagedBundle, EncvolError> {
    stage_bundle_with_policy(
        bundle,
        destination,
        VerificationPolicy::with_signature(signature, public_key_hex),
    )
}

pub fn stage_bundle_with_policy(
    bundle: &Path,
    destination: &Path,
    policy: VerificationPolicy<'_>,
) -> Result<StagedBundle, EncvolError> {
    let (bytes, _) = read_verified_bundle(bundle, policy)?;
    stage_bundle_bytes(&bytes, destination)
}

pub fn stage_bundle_bytes(bytes: &[u8], destination: &Path) -> Result<StagedBundle, EncvolError> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    fs::create_dir_all(destination)
        .map_err(|e| EncvolError::Verification(format!("cannot create staging directory: {e}")))?;
    let mut kernel = None;
    let mut initrd = None;
    let mut uki = None;
    for entry in archive
        .entries()
        .map_err(|_| EncvolError::Verification("invalid installer tar".into()))?
    {
        let mut entry =
            entry.map_err(|_| EncvolError::Verification("invalid installer tar entry".into()))?;
        let path = entry
            .path()
            .map_err(|_| EncvolError::Verification("installer tar path is invalid".into()))?;
        let name = path
            .to_str()
            .ok_or_else(|| EncvolError::Verification("installer tar names must be UTF-8".into()))?
            .to_owned();
        if !matches!(name.as_str(), "kernel" | "initrd" | "installer.efi")
            || !entry.header().entry_type().is_file()
            || entry.size() > MAX_COMPONENT_BYTES
        {
            return Err(EncvolError::Verification(
                "installer bundle contains an unsupported or unsafe entry".into(),
            ));
        }
        let output = destination.join(&name);
        // Staging is intentionally write-once.  A pre-existing component can
        // otherwise be a symlink planted in a reusable staging directory.
        let mut output_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|e| {
                EncvolError::Verification(format!("cannot create installer component: {e}"))
            })?;
        std::io::copy(&mut entry, &mut output_file).map_err(|e| {
            EncvolError::Verification(format!("cannot unpack installer component: {e}"))
        })?;
        match name.as_str() {
            "kernel" => kernel = Some(output),
            "initrd" => initrd = Some(output),
            "installer.efi" => uki = Some(output),
            _ => unreachable!(),
        }
    }
    if (kernel.is_some() || initrd.is_some()) && !(kernel.is_some() && initrd.is_some()) {
        return Err(EncvolError::Verification(
            "bundle must contain both kernel and initrd".into(),
        ));
    }
    if kernel.is_none() && uki.is_none() {
        return Err(EncvolError::Verification(
            "bundle contains no bootable installer".into(),
        ));
    }
    Ok(StagedBundle {
        directory: destination.into(),
        kernel,
        initrd,
        uki,
    })
}

/// Parse the installer tar without extracting it.  This is also called by the
/// verification command, so a signed archive is not reported as usable if it
/// violates the narrow installer-bundle ABI.
pub(crate) fn validate_bundle_structure(bytes: &[u8]) -> Result<(), EncvolError> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut kernel = false;
    let mut initrd = false;
    let mut uki = false;
    for entry in archive
        .entries()
        .map_err(|_| EncvolError::Verification("invalid installer tar".into()))?
    {
        let entry =
            entry.map_err(|_| EncvolError::Verification("invalid installer tar entry".into()))?;
        let path = entry
            .path()
            .map_err(|_| EncvolError::Verification("installer tar path is invalid".into()))?;
        let name = path
            .to_str()
            .ok_or_else(|| EncvolError::Verification("installer tar names must be UTF-8".into()))?;
        if !matches!(name, "kernel" | "initrd" | "installer.efi")
            || !entry.header().entry_type().is_file()
            || entry.size() > MAX_COMPONENT_BYTES
        {
            return Err(EncvolError::Verification(
                "installer bundle contains an unsupported or unsafe entry".into(),
            ));
        }
        let already_seen = match name {
            "kernel" => std::mem::replace(&mut kernel, true),
            "initrd" => std::mem::replace(&mut initrd, true),
            "installer.efi" => std::mem::replace(&mut uki, true),
            _ => unreachable!(),
        };
        if already_seen {
            return Err(EncvolError::Verification(
                "installer bundle contains duplicate components".into(),
            ));
        }
    }
    if kernel != initrd {
        return Err(EncvolError::Verification(
            "bundle must contain both kernel and initrd".into(),
        ));
    }
    if !kernel && !uki {
        return Err(EncvolError::Verification(
            "bundle contains no bootable installer".into(),
        ));
    }
    Ok(())
}
