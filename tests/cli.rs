use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_encvol"))
}

#[test]
fn bundle_command_is_not_public_cli() {
    let output = binary().arg("bundle").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
}

#[test]
fn install_help_hides_bundle_flags() {
    let output = binary().args(["install", "--help"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8_lossy(&output.stdout);
    for removed in [
        "--bundle-version",
        "--bundle-directory",
        "--bundle-signature",
        "--bundle-public-key",
    ] {
        assert!(!help.contains(removed), "{removed} is still visible");
    }
}

#[test]
fn install_execute_without_embedded_bundle_fails_clearly() {
    let output = binary()
        .args([
            "install",
            "--disk",
            "/dev/vda",
            "--rootfs-descriptor",
            "https://127.0.0.1/rootfs.json",
            "--tang-url",
            "http://127.0.0.1:8080",
            "--tang-thumbprint",
            "pin",
            "--recovery-authorized-key",
            "/missing/recovery.pub",
            "--confirm",
            "WIPE:/dev/vda",
            "--execute",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("built without an embedded installer bundle"));
}

#[test]
fn self_install_is_not_public_cli() {
    let output = binary().args(["self-install", "--help"]).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
}

#[test]
fn install_help_presents_live_root_default_and_optional_descriptor() {
    let output = binary().args(["install", "--help"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--rootfs-descriptor"));
    assert!(help.contains("capturing the running root"));
    assert!(!help.contains("--use-live-root"));
}

#[test]
fn install_live_root_execute_without_embedded_bundle_fails_clearly() {
    let output = binary()
        .args([
            "install",
            "--disk",
            "/dev/vda",
            "--tang-url",
            "http://127.0.0.1:8080",
            "--tang-thumbprint",
            "pin",
            "--recovery-authorized-key",
            "/missing/recovery.pub",
            "--confirm",
            "WIPE:/dev/vda",
            "--execute",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("built without an embedded installer bundle"));
}
