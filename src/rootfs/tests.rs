use super::*;
use tempfile::tempdir;

fn descriptor() -> RootfsDescriptor {
    RootfsDescriptor {
        schema_version: 1,
        archive_url: Url::parse("https://example.invalid/rootfs.tar").unwrap(),
        sha256: "a".repeat(64),
        release: "bookworm".into(),
        architecture: "amd64".into(),
        provides: REQUIRED_CAPABILITIES
            .iter()
            .map(|value| (*value).into())
            .collect(),
        format: ArchiveFormat::Tar,
    }
}

#[test]
fn descriptor_round_trip_and_validation() {
    let descriptor = descriptor();
    assert!(descriptor.validate().is_ok());
    let restored: RootfsDescriptor =
        serde_json::from_str(&serde_json::to_string(&descriptor).unwrap()).unwrap();
    assert_eq!(restored.format, ArchiveFormat::Tar);
    let mut invalid = descriptor;
    invalid.architecture = "arm64".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn requires_debian_workspace_components() {
    let dir = tempdir().unwrap();
    assert!(validate_workspace(dir.path()).is_err());
    for path in ["usr/lib/systemd", "usr/bin", "var/lib/dpkg"] {
        fs::create_dir_all(dir.path().join(path)).unwrap();
    }
    fs::write(dir.path().join("usr/lib/systemd/systemd"), b"").unwrap();
    fs::write(dir.path().join("usr/bin/apt"), b"").unwrap();
    fs::write(dir.path().join("var/lib/dpkg/status"), b"").unwrap();
    fs::create_dir_all(dir.path().join("etc")).unwrap();
    fs::write(
        dir.path().join("etc/os-release"),
        "VERSION_CODENAME=bookworm\n",
    )
    .unwrap();
    assert!(validate_workspace(dir.path()).is_ok());
    assert_eq!(workspace_release(dir.path()).unwrap(), "bookworm");
}

fn fixture_workspace(root: &Path) {
    for path in [
        "usr/lib/systemd",
        "usr/bin",
        "var/lib/dpkg",
        "etc",
        "dev",
        "proc",
        "sys",
        "run",
        "tmp",
    ] {
        fs::create_dir_all(root.join(path)).unwrap();
    }
    fs::write(root.join("usr/lib/systemd/systemd"), b"systemd").unwrap();
    fs::write(root.join("usr/bin/apt"), b"apt").unwrap();
    fs::write(root.join("var/lib/dpkg/status"), b"Package: base-files\n").unwrap();
    fs::write(root.join("etc/os-release"), "VERSION_CODENAME=bookworm\n").unwrap();
    fs::write(root.join("dev/transient"), b"must not be packed").unwrap();
    fs::write(root.join("etc/kept"), b"must be packed").unwrap();
}

#[test]
fn packs_fixture_and_writes_matching_descriptor() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir(&root).unwrap();
    fixture_workspace(&root);
    let output = dir.path().join("rootfs.tar");
    let descriptor = pack_workspace(
        &root,
        &output,
        Url::parse("https://example.invalid/rootfs.tar").unwrap(),
        ArchiveFormat::Tar,
    )
    .unwrap();
    assert_eq!(descriptor.sha256, sha256_hex(&fs::read(&output).unwrap()));
    assert!(descriptor_path(&output).is_file());
    let mut archive = tar::Archive::new(fs::File::open(output).unwrap());
    let names = archive
        .entries()
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert!(names.iter().any(|name| name.ends_with("etc/kept")));
    assert!(names.iter().any(|name| name == "./dev/"));
    assert!(!names.iter().any(|name| name.ends_with("dev/transient")));
}

#[test]
fn tar_keeps_runtime_mountpoints_and_excludes_contents() {
    let command = pack_command(
        Path::new("/rootfs"),
        Path::new("/out.tar"),
        ArchiveFormat::TarZst,
    );
    assert!(command.iter().any(|value| value == "--exclude=./dev/*"));
    assert!(command.iter().any(|value| value == "--exclude=./tmp/*"));
    assert!(command.iter().any(|value| value == "--zstd"));
    assert!(command.iter().any(|value| value == "--numeric-owner"));
}

#[test]
fn import_requires_a_partition() {
    assert!(validate_import_source_path(Path::new("/dev/vda1")).is_ok());
    assert!(validate_import_source_path(Path::new("/dev/nvme0n1p2")).is_ok());
    assert!(validate_import_source_path(Path::new("/dev/mapper/vg-root")).is_ok());
    assert!(validate_import_source_path(Path::new("/dev/vda")).is_err());
    assert!(validate_import_source_path(Path::new("/tmp/rootfs.img")).is_err());
}

#[test]
fn commands_select_compression_explicitly() {
    assert!(
        !extraction_command(ArchiveFormat::Tar, Path::new("a"), Path::new("b"))
            .iter()
            .any(|v| v == "--zstd")
    );
    assert!(
        extraction_command(ArchiveFormat::TarZst, Path::new("a"), Path::new("b"))
            .iter()
            .any(|v| v == "--zstd")
    );
    assert_eq!(
        readonly_mount_command(Path::new("/dev/vda1"), Path::new("/tmp/m"))[1],
        "--read-only"
    );
    let bootstrap = debootstrap_command("bookworm", Path::new("/root"), None).unwrap();
    assert!(bootstrap.iter().any(|value| value == "--arch=amd64"));
    assert!(bootstrap
        .iter()
        .any(|value| value == "--include=apt,systemd-sysv"));
}
