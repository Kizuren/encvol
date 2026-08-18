use crate::{
    bundle::{
        bundle_path, download, sha256_hex, signature_path, valid_version,
        validate_bundle_structure, verify_signature, BundleVerification, BundleVerificationResult,
    },
    EncvolError,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Fetch a versioned artifact into a caller-owned directory. Optional signature
/// material is verified with the operator-supplied public key before storing
/// the artifact.
pub fn fetch_bundle(
    base: &url::Url,
    version: &str,
    destination: &Path,
    signature_url: Option<&url::Url>,
    public_key_hex: Option<&str>,
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
    let verification = match (signature_text.as_deref(), public_key_hex) {
        (Some(signature_text), Some(public_key_hex)) => {
            let sig = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                signature_text.trim(),
            )
            .map_err(|_| EncvolError::Verification("signature is not base64".into()))?;
            verify_signature(&artifact, &sig, public_key_hex)?;
            BundleVerification::Signature
        }
        (Some(_), None) => {
            return Err(EncvolError::Verification(
                "signature verification requires --public-key".into(),
            ))
        }
        (None, Some(_)) => {
            return Err(EncvolError::Verification(
                "signature public key requires --signature-url".into(),
            ))
        }
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
