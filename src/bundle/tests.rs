use super::*;
use ed25519_dalek::{Signer, SigningKey};
use flate2::{write::GzEncoder, Compression};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::{
    ffi::OsString,
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
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

fn fixture_public_key() -> &'static str {
    "35b3db59f8b0a95f1a026d1ae18e76c4b46cfeea9b541186314b1d9b98da02ad"
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
fn approved_fixture_verifies_with_an_operator_public_key() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let digest = verify_bundle(
        &root.join("approved-installer.bundle"),
        &root.join("approved-installer.bundle.sig"),
        fixture_public_key(),
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

    assert!(verify_bundle(&artifact, &signature, fixture_public_key()).is_err());
    let result = verify_bundle_with_policy(&artifact, VerificationPolicy::unsigned()).unwrap();
    assert_eq!(result.verification, BundleVerification::None);

    fs::write(&artifact, bundle(&[("unexpected", b"unsafe")])).unwrap();
    assert!(verify_bundle_with_policy(&artifact, VerificationPolicy::unsigned()).is_err());
}

#[test]
fn signature_policy_requires_both_signature_and_public_key() {
    let dir = tempdir().unwrap();
    let artifact = dir.path().join("installer.bundle");
    let signature = dir.path().join("installer.bundle.sig");
    fs::write(&artifact, bundle(&[("installer.efi", b"placeholder")])).unwrap();

    assert!(verify_bundle_with_policy(
        &artifact,
        VerificationPolicy {
            signature: Some(&signature),
            public_key_hex: None,
        },
    )
    .is_err());

    assert!(verify_bundle_with_policy(
        &artifact,
        VerificationPolicy {
            signature: None,
            public_key_hex: Some(fixture_public_key()),
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
        assert!(
            validate_bundle_structure(&bundle_with_entry_type("installer.efi", entry_type,))
                .is_err()
        );
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
    let error = verify_bundle(&artifact, &signature, fixture_public_key())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("untrusted signature input"));

    let wrong_signature =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 64]);
    fs::write(&signature, wrong_signature).unwrap();
    assert!(verify_bundle(&artifact, &signature, fixture_public_key()).is_err());

    fs::copy(fixture.join("approved-installer.bundle.sig"), &signature).unwrap();
    fs::write(&artifact, bundle(&[("installer.efi", b"tampered")])).unwrap();
    assert!(verify_bundle(&artifact, &signature, fixture_public_key()).is_err());
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
    assert!(stage_bundle_with_policy(&artifact, &staging, VerificationPolicy::unsigned()).is_err());
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
