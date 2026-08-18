mod fetch;
mod initrd;
mod paths;
mod stage;
mod transfer;
mod verify;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_bundle.rs"));
}

pub use embedded::EMBEDDED_INSTALLER_BUNDLE;
pub use fetch::fetch_bundle;
pub use initrd::embed_manifest;
pub use paths::{bundle_path, signature_path, valid_version};
pub use stage::{stage_bundle, stage_bundle_bytes, stage_bundle_with_policy, StagedBundle};
pub use transfer::{download, download_to_path, sha256_file, sha256_hex};
pub use verify::{
    verify_bundle, verify_bundle_with_policy, verify_signature, BundleVerification,
    BundleVerificationResult, VerificationPolicy,
};

pub(crate) use stage::validate_bundle_structure;
pub(crate) use verify::read_verified_bundle;

#[cfg(test)]
pub(crate) use initrd::append_newc_entry;
#[cfg(test)]
pub(crate) use stage::MAX_COMPONENT_BYTES;
#[cfg(test)]
pub(crate) use transfer::copy_and_hash;

#[cfg(test)]
mod tests;
