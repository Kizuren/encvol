use crate::{
    bundle::{sha256_hex, validate_bundle_structure},
    EncvolError,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::{fs, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleVerification {
    Signature,
    None,
}

impl BundleVerification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerificationPolicy<'a> {
    pub signature: Option<&'a Path>,
    pub public_key_hex: Option<&'a str>,
}

impl<'a> VerificationPolicy<'a> {
    pub fn unsigned() -> Self {
        Self {
            signature: None,
            public_key_hex: None,
        }
    }

    pub fn with_signature(signature: &'a Path, public_key_hex: &'a str) -> Self {
        Self {
            signature: Some(signature),
            public_key_hex: Some(public_key_hex),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVerificationResult {
    pub sha256: String,
    pub verification: BundleVerification,
}

pub fn verify_signature(
    payload: &[u8],
    signature: &[u8],
    public_key_hex: &str,
) -> Result<(), EncvolError> {
    let key_bytes = hex::decode(public_key_hex)
        .map_err(|_| EncvolError::Verification("signature public key is malformed".into()))?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| EncvolError::Verification("signature public key has wrong length".into()))?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| EncvolError::Verification("signature is malformed".into()))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| EncvolError::Verification("signature public key is invalid".into()))?
        .verify(payload, &signature)
        .map_err(|_| EncvolError::Verification("installer signature did not verify".into()))
}

pub fn verify_bundle(
    bundle: &Path,
    signature: &Path,
    public_key_hex: &str,
) -> Result<String, EncvolError> {
    Ok(verify_bundle_with_policy(
        bundle,
        VerificationPolicy::with_signature(signature, public_key_hex),
    )?
    .sha256)
}

/// Verify according to `policy` and always validate the bundle ABI.  A missing
/// signature is allowed by design, but the caller must emit an appropriate
/// warning because structure-only checks do not authenticate the installer
/// bundle.
pub fn verify_bundle_with_policy(
    bundle: &Path,
    policy: VerificationPolicy<'_>,
) -> Result<BundleVerificationResult, EncvolError> {
    let (_, result) = read_verified_bundle(bundle, policy)?;
    Ok(result)
}

pub(crate) fn read_verified_bundle(
    bundle: &Path,
    policy: VerificationPolicy<'_>,
) -> Result<(Vec<u8>, BundleVerificationResult), EncvolError> {
    let artifact = fs::read(bundle)
        .map_err(|e| EncvolError::Verification(format!("cannot read bundle: {e}")))?;
    let digest = sha256_hex(&artifact);
    let verification = match (policy.signature, policy.public_key_hex) {
        (Some(signature), Some(public_key_hex)) => {
            verify_detached_signature(&artifact, signature, public_key_hex)?;
            BundleVerification::Signature
        }
        (Some(_), None) => {
            return Err(EncvolError::Verification(
                "signature verification requires --public-key".into(),
            ))
        }
        (None, Some(_)) => {
            return Err(EncvolError::Verification(
                "signature public key requires a signature".into(),
            ))
        }
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

fn verify_detached_signature(
    artifact: &[u8],
    signature: &Path,
    public_key_hex: &str,
) -> Result<(), EncvolError> {
    let text = fs::read_to_string(signature)
        .map_err(|e| EncvolError::Verification(format!("cannot read signature: {e}")))?;
    let sig = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text.trim())
        .map_err(|_| EncvolError::Verification("signature is not base64".into()))?;
    verify_signature(artifact, &sig, public_key_hex)
}
