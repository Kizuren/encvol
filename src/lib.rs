//! Core validation and planning primitives for `encvol`.
//!
//! Keeping policy and command generation separate from host I/O makes the
//! safety-critical parts directly testable and prevents preflight from writing
//! to the selected disk.

pub mod bundle;
pub mod handoff;
pub mod installer;
pub mod manifest;
pub mod network;
pub mod preflight;
pub mod rootfs;
pub mod runtime;
pub mod safety;
pub mod secrets;
pub mod self_install;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncvolError {
    #[error("unsafe target disk: {0}")]
    UnsafeDisk(String),
    #[error("unsupported host: {0}")]
    Unsupported(String),
    #[error("invalid manifest: {0}")]
    Manifest(String),
    #[error("verification failed: {0}")]
    Verification(String),
}
