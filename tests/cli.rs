use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    thread,
};
use tempfile::tempdir;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_encvol"))
}

fn copy_fixture(directory: &Path) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    fs::copy(
        fixtures.join("approved-installer.bundle"),
        directory.join("encvol-installer-fixture.bundle"),
    )
    .unwrap();
    fs::copy(
        fixtures.join("approved-installer.bundle.sig"),
        directory.join("encvol-installer-fixture.bundle.sig"),
    )
    .unwrap();
}

#[test]
fn bundle_verify_is_strict_by_default() {
    let dir = tempdir().unwrap();
    copy_fixture(dir.path());
    let output = binary()
        .args(["bundle", "verify", "--version", "fixture", "--directory"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("verified installer fixture"));

    fs::remove_file(dir.path().join("encvol-installer-fixture.bundle.sig")).unwrap();
    let output = binary()
        .args(["bundle", "verify", "--version", "fixture", "--directory"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());

    fs::write(
        dir.path().join("encvol-installer-fixture.bundle.sig"),
        "not base64",
    )
    .unwrap();
    let output = binary()
        .args(["bundle", "verify", "--version", "fixture", "--directory"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());

    fs::write(
        dir.path().join("encvol-installer-fixture.bundle.sig"),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0_u8; 64]),
    )
    .unwrap();
    let output = binary()
        .args(["bundle", "verify", "--version", "fixture", "--directory"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());

    copy_fixture(dir.path());
    fs::write(
        dir.path().join("encvol-installer-fixture.bundle"),
        b"tampered bundle",
    )
    .unwrap();
    let output = binary()
        .args(["bundle", "verify", "--version", "fixture", "--directory"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn unsigned_local_bundle_requires_explicit_opt_in_and_warns() {
    let dir = tempdir().unwrap();
    copy_fixture(dir.path());
    fs::write(
        dir.path().join("encvol-installer-fixture.bundle.sig"),
        "not a signature\n",
    )
    .unwrap();

    let output = binary()
        .args(["bundle", "verify", "--version", "fixture", "--directory"])
        .arg(dir.path())
        .arg("--allow-unsigned-bundle")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "WARNING: installer signature verification disabled"
    );
}

#[test]
fn unsigned_bypass_does_not_allow_an_unsafe_bundle() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("encvol-installer-fixture.bundle"),
        b"not a tar archive",
    )
    .unwrap();
    let output = binary()
        .args(["bundle", "verify", "--version", "fixture", "--directory"])
        .arg(dir.path())
        .arg("--allow-unsigned-bundle")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap(),
        "WARNING: installer signature verification disabled"
    );
}

#[test]
fn bundle_fetch_cannot_bypass_a_bad_downloaded_signature() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            let body = if request.starts_with("GET /encvol-installer-fixture.bundle ") {
                fs::read(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/approved-installer.bundle"),
                )
                .unwrap()
            } else {
                b"not a detached signature\n".to_vec()
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    let destination = tempdir().unwrap();
    let output = binary()
        .args([
            "bundle",
            "fetch",
            "--version",
            "fixture",
            "--base-url",
            &format!("http://{address}/"),
            "--directory",
        ])
        .arg(destination.path())
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    assert!(!destination
        .path()
        .join("encvol-installer-fixture.bundle")
        .exists());
}

#[test]
fn bundle_commands_reject_path_like_versions() {
    let output = binary()
        .args(["bundle", "verify", "--version", ".."])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
