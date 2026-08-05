use crate::EncvolError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    thread,
};

/// Release key for the installer artifact channel. Releases are signed over the
/// exact bundle bytes; this is not a checksum-only authenticity check.
pub const RELEASE_PUBLIC_KEY_HEX: &str =
    "35b3db59f8b0a95f1a026d1ae18e76c4b46cfeea9b541186314b1d9b98da02ad";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleVerification {
    Signature,
    SignatureAndChecksum,
    Checksum,
    None,
}

impl BundleVerification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::SignatureAndChecksum => "signature+checksum",
            Self::Checksum => "checksum",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerificationPolicy<'a> {
    pub signature: Option<&'a Path>,
    pub checksum: Option<&'a str>,
}

impl<'a> VerificationPolicy<'a> {
    pub fn unsigned() -> Self {
        Self {
            signature: None,
            checksum: None,
        }
    }

    pub fn with_signature(signature: &'a Path) -> Self {
        Self {
            signature: Some(signature),
            checksum: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVerificationResult {
    pub sha256: String,
    pub verification: BundleVerification,
}

const MAX_COMPONENT_BYTES: u64 = 128 * 1024 * 1024;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn verify_signature(
    payload: &[u8],
    signature: &[u8],
    public_key_hex: &str,
) -> Result<(), EncvolError> {
    let key_bytes = hex::decode(public_key_hex)
        .map_err(|_| EncvolError::Verification("release public key is malformed".into()))?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| EncvolError::Verification("release public key has wrong length".into()))?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| EncvolError::Verification("signature is malformed".into()))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| EncvolError::Verification("release public key is invalid".into()))?
        .verify(payload, &signature)
        .map_err(|_| EncvolError::Verification("installer signature did not verify".into()))
}

pub fn verify_bundle(bundle: &Path, signature: &Path) -> Result<String, EncvolError> {
    Ok(verify_bundle_with_policy(bundle, VerificationPolicy::with_signature(signature))?.sha256)
}

/// Verify according to `policy` and always validate the bundle ABI.  A missing
/// signature is allowed by design, but the caller must emit an appropriate
/// warning because checksum-only or structure-only checks do not authenticate
/// the installer bundle.
pub fn verify_bundle_with_policy(
    bundle: &Path,
    policy: VerificationPolicy<'_>,
) -> Result<BundleVerificationResult, EncvolError> {
    let (_, result) = read_verified_bundle(bundle, policy)?;
    Ok(result)
}

fn read_verified_bundle(
    bundle: &Path,
    policy: VerificationPolicy<'_>,
) -> Result<(Vec<u8>, BundleVerificationResult), EncvolError> {
    let artifact = fs::read(bundle)
        .map_err(|e| EncvolError::Verification(format!("cannot read bundle: {e}")))?;
    let digest = sha256_hex(&artifact);
    if let Some(expected) = policy.checksum {
        verify_checksum(&digest, expected)?;
    }
    let verification = match (policy.signature, policy.checksum) {
        (Some(signature), Some(_)) => {
            verify_detached_signature(&artifact, signature)?;
            BundleVerification::SignatureAndChecksum
        }
        (Some(signature), None) => {
            verify_detached_signature(&artifact, signature)?;
            BundleVerification::Signature
        }
        (None, Some(_)) => BundleVerification::Checksum,
        (None, None) => BundleVerification::None,
    };
    validate_bundle_structure(&artifact)?;
    Ok((
        artifact,
        BundleVerificationResult {
            sha256: digest,
            verification,
        },
    ))
}

fn normalize_checksum(checksum: &str) -> Result<String, EncvolError> {
    let checksum = checksum.trim();
    let checksum = checksum
        .strip_prefix("sha256:")
        .or_else(|| checksum.strip_prefix("SHA256:"))
        .unwrap_or(checksum);
    if checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(checksum.to_ascii_lowercase())
    } else {
        Err(EncvolError::Verification(
            "bundle SHA-256 checksum must be 64 hexadecimal characters".into(),
        ))
    }
}

fn verify_checksum(actual: &str, expected: &str) -> Result<(), EncvolError> {
    let expected = normalize_checksum(expected)?;
    if actual == expected {
        Ok(())
    } else {
        Err(EncvolError::Verification(
            "bundle SHA-256 checksum did not verify".into(),
        ))
    }
}

fn verify_detached_signature(artifact: &[u8], signature: &Path) -> Result<(), EncvolError> {
    let text = fs::read_to_string(signature)
        .map_err(|e| EncvolError::Verification(format!("cannot read signature: {e}")))?;
    let sig = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text.trim())
        .map_err(|_| EncvolError::Verification("signature is not base64".into()))?;
    verify_signature(artifact, &sig, RELEASE_PUBLIC_KEY_HEX)
}

pub fn download(url: &url::Url) -> Result<Vec<u8>, EncvolError> {
    let response = ureq::get(url.as_str())
        .call()
        // Transport libraries commonly include the complete URL in their
        // diagnostic, including any accidentally supplied userinfo.  URLs
        // are inputs here, so keep that value out of caller-visible errors.
        .map_err(|_| EncvolError::Verification("download failed".into()))?;
    let mut reader = response.into_reader();
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut out)
        .map_err(|_| EncvolError::Verification("download failed".into()))?;
    Ok(out)
}

pub fn download_to_path(url: &url::Url, destination: &Path) -> Result<String, EncvolError> {
    let response = ureq::get(url.as_str())
        .call()
        // Keep potentially sensitive URL userinfo out of diagnostics.
        .map_err(|_| EncvolError::Verification("download failed".into()))?;
    let file = fs::File::create(destination)
        .map_err(|e| EncvolError::Unsupported(format!("cannot create download cache: {e}")))?;
    copy_and_hash(response.into_reader(), file)
}

fn copy_and_hash(mut reader: impl Read, mut writer: impl Write) -> Result<String, EncvolError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| EncvolError::Verification("download failed".into()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|e| EncvolError::Unsupported(format!("cannot write download cache: {e}")))?;
    }
    writer
        .flush()
        .map_err(|e| EncvolError::Unsupported(format!("cannot flush download cache: {e}")))?;
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone)]
pub struct StagedBundle {
    pub directory: PathBuf,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub uki: Option<PathBuf>,
}

fn append_newc_entry(output: &mut Vec<u8>, name: &str, data: &[u8]) {
    append_newc_node(output, name, data, 0o100600, 1);
}

fn append_newc_dir(output: &mut Vec<u8>, name: &str) {
    append_newc_node(output, name, &[], 0o040700, 2);
}

fn append_newc_node(output: &mut Vec<u8>, name: &str, data: &[u8], mode: u32, nlink: u32) {
    let fields = [
        0_u32,
        mode,
        0,
        0,
        nlink,
        0,
        data.len() as u32,
        0,
        0,
        0,
        0,
        (name.len() + 1) as u32,
        0,
    ];
    output.extend_from_slice(b"070701");
    for field in fields {
        output.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    output.extend_from_slice(data);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
}

/// Concatenate a newc CPIO overlay to the initramfs. Linux initramfs accepts
/// concatenated archives in some formats, but Debian's zstd-compressed images
/// are more reliable when the manifest is inserted into the existing CPIO
/// stream before the final trailer and then recompressed as one stream.  That
/// keeps the exact preflighted configuration available in RAM without modifying
/// the signed base installer artifact.
pub fn embed_manifest(bundle: &mut StagedBundle, manifest: &[u8]) -> Result<(), EncvolError> {
    let initrd = bundle.initrd.as_ref().ok_or_else(|| {
        EncvolError::Verification("installer needs kernel/initrd to embed its manifest".into())
    })?;
    let initrd_bytes = fs::read(initrd)
        .map_err(|e| EncvolError::Verification(format!("cannot read staged initrd: {e}")))?;
    let updated = embed_manifest_for_initrd(&initrd_bytes, manifest)?;
    fs::write(initrd, updated)
        .map_err(|e| EncvolError::Verification(format!("cannot embed installer manifest: {e}")))?;
    Ok(())
}

fn manifest_cpio_entries(manifest: &[u8]) -> Vec<u8> {
    let mut entries = Vec::new();
    append_newc_dir(&mut entries, "etc/encvol");
    append_newc_entry(&mut entries, "etc/encvol/manifest.json", manifest);
    entries
}

fn embed_manifest_for_initrd(initrd: &[u8], manifest: &[u8]) -> Result<Vec<u8>, EncvolError> {
    if initrd.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let cpio = zstd_decompress(initrd)?;
        let cpio = insert_manifest_entries(&cpio, manifest)?;
        return zstd_compress(&cpio);
    }
    if initrd.starts_with(&[0x1f, 0x8b]) {
        let mut cpio = Vec::new();
        GzDecoder::new(initrd).read_to_end(&mut cpio).map_err(|e| {
            EncvolError::Verification(format!("cannot decompress initrd for manifest: {e}"))
        })?;
        let cpio = insert_manifest_entries(&cpio, manifest)?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&cpio).map_err(|e| {
            EncvolError::Verification(format!("cannot compress manifest overlay: {e}"))
        })?;
        return encoder.finish().map_err(|e| {
            EncvolError::Verification(format!("cannot finish manifest overlay compression: {e}"))
        });
    }
    insert_manifest_entries(initrd, manifest)
}

fn insert_manifest_entries(cpio: &[u8], manifest: &[u8]) -> Result<Vec<u8>, EncvolError> {
    let trailer = find_first_newc_trailer(cpio).ok_or_else(|| {
        EncvolError::Verification("installer initrd is not a readable newc archive".into())
    })?;
    let mut updated = Vec::with_capacity(cpio.len() + manifest.len() + 512);
    updated.extend_from_slice(&cpio[..trailer]);
    updated.extend_from_slice(&manifest_cpio_entries(manifest));
    updated.extend_from_slice(&cpio[trailer..]);
    Ok(updated)
}

fn find_first_newc_trailer(cpio: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while offset + 110 <= cpio.len() {
        match &cpio[offset..offset + 6] {
            b"070701" | b"070702" => {}
            _ if cpio[offset] == 0 => {
                offset += 1;
                continue;
            }
            _ => return None,
        }

        let filesize = parse_newc_hex(cpio, offset + 54)? as usize;
        let namesize = parse_newc_hex(cpio, offset + 94)? as usize;
        let name_start = offset + 110;
        let name_end = name_start.checked_add(namesize)?;
        if name_end > cpio.len() || namesize == 0 {
            return None;
        }
        let name = &cpio[name_start..name_end - 1];
        if name == b"TRAILER!!!" {
            return Some(offset);
        }
        let data_start = align4(name_end);
        let data_end = data_start.checked_add(filesize)?;
        if data_end > cpio.len() {
            return None;
        }
        offset = align4(data_end);
    }
    None
}

fn parse_newc_hex(cpio: &[u8], offset: usize) -> Option<u32> {
    let field = cpio.get(offset..offset + 8)?;
    let text = std::str::from_utf8(field).ok()?;
    u32::from_str_radix(text, 16).ok()
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn zstd_decompress(initrd: &[u8]) -> Result<Vec<u8>, EncvolError> {
    zstd_filter(
        &["-q", "-d", "-c"],
        initrd,
        "zstd failed while decompressing installer initrd",
    )
}

fn zstd_filter(args: &[&str], input: &[u8], failure: &str) -> Result<Vec<u8>, EncvolError> {
    let mut child = ProcessCommand::new("zstd")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            EncvolError::Verification(format!("cannot start zstd for initrd manifest: {e}"))
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| EncvolError::Verification("cannot open zstd stdin".into()))?;
    let input = input.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output().map_err(|e| {
        EncvolError::Verification(format!("cannot finish zstd initrd decompression: {e}"))
    })?;
    writer
        .join()
        .map_err(|_| EncvolError::Verification("zstd input writer panicked".into()))?
        .map_err(|e| EncvolError::Verification(format!("cannot write input to zstd: {e}")))?;
    if !output.status.success() {
        return Err(EncvolError::Verification(failure.into()));
    }
    Ok(output.stdout)
}

fn zstd_compress(cpio: &[u8]) -> Result<Vec<u8>, EncvolError> {
    zstd_filter(
        &["-q", "-1", "-c"],
        cpio,
        "zstd failed while compressing manifest overlay",
    )
}

/// Fetch a versioned artifact into a caller-owned directory.  Optional
/// signature/checksum material is verified before storing the artifact.
pub fn fetch_bundle(
    base: &url::Url,
    version: &str,
    destination: &Path,
    signature_url: Option<&url::Url>,
    checksum: Option<&str>,
) -> Result<(PathBuf, Option<PathBuf>, BundleVerificationResult), EncvolError> {
    if !valid_version(version) {
        return Err(EncvolError::Verification("invalid bundle version".into()));
    }
    fs::create_dir_all(destination)
        .map_err(|e| EncvolError::Verification(format!("cannot create bundle directory: {e}")))?;
    let artifact_url = base
        .join(&format!("encvol-installer-{version}.bundle"))
        .map_err(|_| EncvolError::Verification("invalid bundle URL".into()))?;
    let artifact = download(&artifact_url)?;
    let signature_text = if let Some(signature_url) = signature_url {
        let signature = download(signature_url)?;
        Some(
            std::str::from_utf8(&signature)
                .map_err(|_| EncvolError::Verification("signature is not UTF-8 base64".into()))?
                .to_owned(),
        )
    } else {
        None
    };
    let digest = sha256_hex(&artifact);
    if let Some(expected) = checksum {
        verify_checksum(&digest, expected)?;
    }
    let verification = match (signature_text.as_deref(), checksum) {
        (Some(signature_text), Some(_)) => {
            let sig = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                signature_text.trim(),
            )
            .map_err(|_| EncvolError::Verification("signature is not base64".into()))?;
            verify_signature(&artifact, &sig, RELEASE_PUBLIC_KEY_HEX)?;
            BundleVerification::SignatureAndChecksum
        }
        (Some(signature_text), None) => {
            let sig = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                signature_text.trim(),
            )
            .map_err(|_| EncvolError::Verification("signature is not base64".into()))?;
            verify_signature(&artifact, &sig, RELEASE_PUBLIC_KEY_HEX)?;
            BundleVerification::Signature
        }
        (None, Some(_)) => BundleVerification::Checksum,
        (None, None) => BundleVerification::None,
    };
    validate_bundle_structure(&artifact)?;
    let bundle = bundle_path(destination, version);
    fs::write(&bundle, artifact)
        .map_err(|e| EncvolError::Verification(format!("cannot store bundle: {e}")))?;
    let signature_path = if let Some(signature_text) = signature_text {
        let signature = signature_path(destination, version);
        fs::write(&signature, signature_text)
            .map_err(|e| EncvolError::Verification(format!("cannot store signature: {e}")))?;
        Some(signature)
    } else {
        None
    };
    Ok((
        bundle,
        signature_path,
        BundleVerificationResult {
            sha256: digest,
            verification,
        },
    ))
}

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

/// Extract only the three defined artifact paths, after the requested bundle
/// verification. `tar` is parsed directly so path traversal and symlinks are
/// rejected.
pub fn stage_bundle(
    bundle: &Path,
    signature: &Path,
    destination: &Path,
) -> Result<StagedBundle, EncvolError> {
    stage_bundle_with_policy(
        bundle,
        destination,
        VerificationPolicy::with_signature(signature),
    )
}

pub fn stage_bundle_with_policy(
    bundle: &Path,
    destination: &Path,
    policy: VerificationPolicy<'_>,
) -> Result<StagedBundle, EncvolError> {
    let (bytes, _) = read_verified_bundle(bundle, policy)?;
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
fn validate_bundle_structure(bytes: &[u8]) -> Result<(), EncvolError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::{
        ffi::OsString,
        io::{Cursor, Read},
        path::PathBuf,
    };
    use tar::{Builder, EntryType, Header};
    use tempfile::tempdir;

    fn bundle(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut archive = Builder::new(&mut out);
            for (name, body) in entries {
                let mut header = Header::new_ustar();
                header.set_size(body.len() as u64);
                header.set_mode(0o600);
                header.set_cksum();
                archive
                    .append_data(&mut header, *name, Cursor::new(*body))
                    .unwrap();
            }
            archive.finish().unwrap();
        }
        out
    }

    fn bundle_with_entry_type(name: &str, entry_type: EntryType) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut archive = Builder::new(&mut out);
            let mut header = Header::new_ustar();
            header.set_size(0);
            header.set_mode(0o600);
            header.set_entry_type(entry_type);
            archive
                .append_data(&mut header, name, Cursor::new([]))
                .unwrap();
            archive.finish().unwrap();
        }
        out
    }

    fn oversized_bundle() -> Vec<u8> {
        let mut header = Header::new_ustar();
        header.set_path("installer.efi").unwrap();
        header.set_size(MAX_COMPONENT_BYTES + 1);
        header.set_mode(0o600);
        header.set_cksum();
        let mut out = header.as_bytes().to_vec();
        out.extend_from_slice(&[0; 1024]);
        out
    }

    fn bundle_with_raw_name(name: &[u8]) -> Vec<u8> {
        let mut out = bundle(&[("installer.efi", b"unsafe")]);
        assert!(name.len() < 100);
        out[..100].fill(0);
        out[..name.len()].copy_from_slice(name);
        out[148..156].fill(b' ');
        let checksum: u32 = out[..512].iter().map(|byte| u32::from(*byte)).sum();
        let encoded = format!("{checksum:06o}\0 ");
        out[148..156].copy_from_slice(encoded.as_bytes());
        out
    }
    #[test]
    fn digest_is_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn dotted_versions_do_not_become_path_extensions() {
        let directory = Path::new("/var/lib/encvol/releases");
        assert_eq!(
            bundle_path(directory, "0.0.0-qemu"),
            directory.join("encvol-installer-0.0.0-qemu.bundle")
        );
        assert_eq!(
            signature_path(directory, "0.0.0-qemu"),
            directory.join("encvol-installer-0.0.0-qemu.bundle.sig")
        );
    }

    #[test]
    fn verifies_ed25519_signature() {
        let secret = SigningKey::from_bytes(&[7; 32]);
        let p = b"installer";
        let sig = secret.sign(p);
        assert!(verify_signature(
            p,
            &sig.to_bytes(),
            &hex::encode(secret.verifying_key().to_bytes())
        )
        .is_ok());
        assert!(verify_signature(
            b"other",
            &sig.to_bytes(),
            &hex::encode(secret.verifying_key().to_bytes())
        )
        .is_err());
    }

    #[test]
    fn approved_fixture_verifies_under_the_pinned_release_key() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let digest = verify_bundle(
            &root.join("approved-installer.bundle"),
            &root.join("approved-installer.bundle.sig"),
        )
        .unwrap();
        assert_eq!(
            digest,
            "45a0411266ae7d50c423ee8599933f8d155512eec0e79f01468be7ec005cd60b"
        );
    }

    #[test]
    fn unsigned_policy_validates_structure_and_reports_none() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("installer.bundle");
        let signature = dir.path().join("installer.bundle.sig");
        fs::write(&artifact, bundle(&[("installer.efi", b"placeholder")])).unwrap();

        assert!(verify_bundle(&artifact, &signature).is_err());
        let result = verify_bundle_with_policy(&artifact, VerificationPolicy::unsigned()).unwrap();
        assert_eq!(result.verification, BundleVerification::None);

        fs::write(&artifact, bundle(&[("unexpected", b"unsafe")])).unwrap();
        assert!(verify_bundle_with_policy(&artifact, VerificationPolicy::unsigned()).is_err());
    }

    #[test]
    fn checksum_policy_accepts_normalized_sha256_and_rejects_mismatch() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("installer.bundle");
        let bytes = bundle(&[("installer.efi", b"placeholder")]);
        let digest = sha256_hex(&bytes);
        fs::write(&artifact, bytes).unwrap();

        let upper = format!("SHA256:{}", digest.to_ascii_uppercase());
        let result = verify_bundle_with_policy(
            &artifact,
            VerificationPolicy {
                signature: None,
                checksum: Some(&upper),
            },
        )
        .unwrap();
        assert_eq!(result.sha256, digest);
        assert_eq!(result.verification, BundleVerification::Checksum);

        assert!(verify_bundle_with_policy(
            &artifact,
            VerificationPolicy {
                signature: None,
                checksum: Some(&"0".repeat(64)),
            },
        )
        .is_err());
    }

    #[test]
    fn rejects_duplicate_and_partial_boot_components() {
        assert!(validate_bundle_structure(&bundle(&[("kernel", b"a")])).is_err());
        assert!(validate_bundle_structure(&bundle(&[
            ("installer.efi", b"a"),
            ("installer.efi", b"b"),
        ]))
        .is_err());
    }

    #[test]
    fn accepts_each_supported_boot_component_layout() {
        for artifact in [
            bundle(&[("kernel", b"kernel"), ("initrd", b"initrd")]),
            bundle(&[("installer.efi", b"efi")]),
            bundle(&[
                ("kernel", b"kernel"),
                ("initrd", b"initrd"),
                ("installer.efi", b"efi"),
            ]),
        ] {
            assert!(validate_bundle_structure(&artifact).is_ok());
        }
    }

    #[test]
    fn rejects_unsafe_tar_entry_types_and_paths() {
        for entry_type in [
            EntryType::Directory,
            EntryType::Symlink,
            EntryType::Link,
            EntryType::Fifo,
            EntryType::Block,
            EntryType::Char,
        ] {
            assert!(validate_bundle_structure(&bundle_with_entry_type(
                "installer.efi",
                entry_type,
            ))
            .is_err());
        }
        for name in [
            b"../installer.efi".as_slice(),
            b"/installer.efi",
            b"nested/installer.efi",
            b"installer.efi/child",
            b"./installer.efi",
        ] {
            assert!(validate_bundle_structure(&bundle_with_raw_name(name)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_tar_entry_names() {
        let mut out = Vec::new();
        {
            let mut archive = Builder::new(&mut out);
            let mut header = Header::new_ustar();
            header.set_size(0);
            header.set_mode(0o600);
            let name = PathBuf::from(OsString::from_vec(vec![b'i', b'n', b'v', 0xff]));
            archive
                .append_data(&mut header, name, Cursor::new([]))
                .unwrap();
            archive.finish().unwrap();
        }
        assert!(validate_bundle_structure(&out).is_err());
    }

    #[test]
    fn rejects_corrupt_and_oversized_archives() {
        assert!(validate_bundle_structure(b"not an installer tar").is_err());
        assert!(validate_bundle_structure(&oversized_bundle()).is_err());
    }

    #[test]
    fn malformed_wrong_and_tampered_signatures_are_strictly_rejected() {
        let dir = tempdir().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let artifact = dir.path().join("installer.bundle");
        let signature = dir.path().join("installer.bundle.sig");
        fs::copy(fixture.join("approved-installer.bundle"), &artifact).unwrap();
        fs::copy(fixture.join("approved-installer.bundle.sig"), &signature).unwrap();

        fs::write(&signature, "untrusted signature input\n").unwrap();
        let error = verify_bundle(&artifact, &signature)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("untrusted signature input"));

        let wrong_signature =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 64]);
        fs::write(&signature, wrong_signature).unwrap();
        assert!(verify_bundle(&artifact, &signature).is_err());

        fs::copy(fixture.join("approved-installer.bundle.sig"), &signature).unwrap();
        fs::write(&artifact, bundle(&[("installer.efi", b"tampered")])).unwrap();
        assert!(verify_bundle(&artifact, &signature).is_err());
        assert!(verify_bundle_with_policy(&artifact, VerificationPolicy::unsigned()).is_ok());
    }

    #[test]
    fn stages_only_after_structural_validation_and_never_overwrites_components() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("installer.bundle");
        let staging = dir.path().join("staging");
        fs::write(
            &artifact,
            bundle(&[("kernel", b"kernel"), ("initrd", b"initrd")]),
        )
        .unwrap();
        let staged =
            stage_bundle_with_policy(&artifact, &staging, VerificationPolicy::unsigned()).unwrap();
        assert_eq!(fs::read(staged.kernel.unwrap()).unwrap(), b"kernel");
        assert_eq!(fs::read(staged.initrd.unwrap()).unwrap(), b"initrd");
        assert!(
            stage_bundle_with_policy(&artifact, &staging, VerificationPolicy::unsigned()).is_err()
        );
    }

    #[test]
    fn version_is_a_single_safe_path_component() {
        for version in ["1", "1.2.3", "rc-1", "build_42"] {
            assert!(valid_version(version), "{version}");
        }
        for version in ["", "..", "1..2", "../x", "x/y", "x\\y", " space"] {
            assert!(!valid_version(version), "{version}");
        }
    }

    #[test]
    fn download_errors_do_not_echo_url_credentials() {
        let url = url::Url::parse("http://bundle-user:bundle-password@127.0.0.1:9/").unwrap();
        let error = download(&url).unwrap_err().to_string();
        assert!(!error.contains("bundle-user"));
        assert!(!error.contains("bundle-password"));
    }

    #[test]
    fn streamed_download_cache_hashes_written_bytes() {
        let mut out = Vec::new();
        let digest = copy_and_hash(Cursor::new(b"rootfs-bytes"), &mut out).unwrap();
        assert_eq!(out, b"rootfs-bytes");
        assert_eq!(digest, sha256_hex(b"rootfs-bytes"));
    }

    #[test]
    fn embeds_manifest_as_cpio_overlay() {
        let dir = tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        let mut base = Vec::new();
        append_newc_entry(&mut base, "init", b"#!/bin/sh\n");
        append_newc_entry(&mut base, "TRAILER!!!", &[]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&base).unwrap();
        fs::write(&initrd, encoder.finish().unwrap()).unwrap();
        let mut staged = StagedBundle {
            directory: dir.path().into(),
            kernel: Some(dir.path().join("kernel")),
            initrd: Some(initrd.clone()),
            uki: None,
        };
        embed_manifest(&mut staged, b"{\"schema_version\":1}").unwrap();
        let bytes = fs::read(initrd).unwrap();
        assert!(bytes.starts_with(b"\x1f\x8b"));
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert!(decoded
            .windows(b"etc/encvol/manifest.json".len())
            .any(|part| part == b"etc/encvol/manifest.json"));
        let manifest = decoded
            .windows(b"{\"schema_version\":1}".len())
            .any(|part| part == b"{\"schema_version\":1}");
        assert!(manifest);
    }
}
