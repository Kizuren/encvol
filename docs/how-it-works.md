# How encvol Works

This document explains the design and operational model behind `encvol`.
README.md is limited to usage commands.

## High-Level Flow

1. Decide whether to capture the running root filesystem or use a prebuilt Debian-compatible amd64 rootfs descriptor.
2. If using a prebuilt rootfs, publish the archive and descriptor over HTTPS.
3. Run preflight against the target disk using a release `encvol` binary that contains its RAM installer.
4. Run `install` without `--execute` to review the generated plan.
5. Run `install --execute` to stage the embedded installer and perform a one-time boot handoff.
6. The RAM installer revalidates safety conditions, stages or downloads and verifies the rootfs archive, then replaces the selected disk.

## Rootfs Descriptor vs Installation Manifest

The rootfs descriptor is portable artifact metadata. It records the archive URL,
archive SHA-256, release, architecture, archive format, and required rootfs
capabilities.

The installation manifest is host-specific. `install` creates it locally by
combining either the live-root capture source or a descriptor with the selected
disk, captured network configuration, Tang URL and thumbprint, recovery SSH
key, and layout settings.

Keeping these separate lets one rootfs artifact be reused across hosts without
embedding target-specific secrets or disk choices in the artifact.

## Embedded Installer Trust

Normal users do not fetch, verify, or select installer bundles at runtime. A
production `encvol` binary is built with one installer bundle embedded into the
executable, and `install --execute` stages that embedded bundle before adding
the host-specific manifest to the initrd.

Bundle fetch, signature verification, and tar ABI validation remain library,
test, and packaging-script concerns. Release packaging builds a bootstrap
binary that is allowed to omit the embedded installer, creates the installer
bundle, then builds the final release binary with `ENCVOL_INSTALLER_BUNDLE`
pointing at that generated bundle. Ordinary release builds fail if no bundle is
provided.

Rootfs SHA-256 verification remains separate. The RAM installer checks the
downloaded rootfs bytes against the descriptor before the first destructive disk
operation.

## Disk Safety Model

The selected installation target must be a direct whole-disk `/dev/<disk>` path.
Partitions, mapper devices, loop devices, aliases, and symlinks are refused.
Mounted non-root target disks are refused with the mounted source and target
paths. The running root's parent disk is allowed only through the in-place
staging flow.

The same exact confirmation is required on the client and in the RAM installer:

```text
WIPE:/dev/the-selected-disk
```

Preflight does not write to the host. The destructive path is only entered by
`install --execute` after embedded-installer staging and the selected one-time
boot handoff.

## Handoff Methods

Preflight chooses the first supported handoff:

1. `kexec`
2. UEFI BootNext
3. GRUB one-shot boot

The handoff is intended to boot the installer once. If the installer cannot
boot, later boots should follow the host's normal boot order.

## RAM Installer

The hidden `installer-run` command is the executable half of the installer. It
requires the `encvol.installer=1` kernel command-line flag and a RAM-backed root
unless an internal test bypass is used.

The direct descriptor runtime path:

1. validates the manifest and disk again
2. confirms the target disk is not mounted
3. downloads the rootfs archive into RAM-backed storage
4. verifies the rootfs SHA-256
5. wipes and partitions the target disk
6. creates LUKS2, LVM, root, swap, and optional data volumes
7. extracts the rootfs
8. writes network, fstab, crypttab, GRUB, and recovery SSH configuration
9. binds the LUKS slot to Tang using the pinned Tang thumbprint
10. installs bootloader and regenerates initramfs

The in-place runtime path first creates a temporary ext4 staging partition at
the end of the selected disk. It uses existing end-of-disk free space when
available; otherwise it shrinks only a final ext4 partition and never moves
partitions. After the staged archive verifies, every non-staging partition on
the selected disk is erased and replaced by the encrypted encvol layout.

The LUKS recovery passphrase is supplied to commands through stdin. It is not
placed in command arguments, environment variables, manifests, ESP files, or
logs.

## Unlock Paths

Normal boot unlock uses Clevis bound to Tang. The manifest carries the Tang URL
and pinned Tang thumbprint, and the installer binds the LUKS slot using that
trust material instead of accepting an interactive advertisement.

Recovery unlock uses Dropbear in the target initramfs on port 2222. The supplied
OpenSSH public key is written with forced-command restrictions so the SSH
session can only run the unlock helper, cannot allocate a pty, and exits after
unlock.

## Installer Bundle ABI

The bundle ABI is internal to release packaging and tests. A bundle is a tar
archive named:

```text
encvol-installer-VERSION.bundle
```

It may contain only regular files named:

```text
kernel
initrd
installer.efi
```

`kernel` and `initrd` must appear together. UEFI fallback handoff needs
`installer.efi`.

The initramfs must invoke:

```text
encvol installer-run --manifest /etc/encvol/manifest.json
```

During staging, `encvol` embeds the generated manifest into the initramfs as a
CPIO overlay. Generated bundles are not committed to the repository.

## Rootfs Archive Rules

`rootfs pack` validates that the workspace contains Debian-compatible systemd
and apt components, reads the Debian codename from `/etc/os-release`, and writes
a descriptor next to the archive.

Archives preserve numeric ownership, ACLs, xattrs, and sparse extents.
Transient contents under `dev`, `proc`, `sys`, `run`, and `tmp` are excluded
while their mountpoint directories remain.

`rootfs import` accepts a filesystem partition or mapped filesystem block
device, mounts it read-only, then uses the same validation and packaging path as
`rootfs pack`.

## QEMU Harness

The QEMU harness builds disposable rootfs, source, and target images. It uses
fresh qcow2 overlays and a private TAP/bridge network with local HTTPS and Tang
services. It never accepts a host block-device target.

The fixture builder may contact the Debian mirror while building artifacts.
Guest cases use only local fixture services after that.

Artifacts are written below:

```text
/var/tmp/encvol-qemu
```

Successful runs remove reusable qcow2 disks unless `--keep-artifacts` is used.
Logs, manifests, disk hashes, and JUnit results remain available for review.

## Source Layout

The larger source modules are directory modules:

```text
src/bundle/
  fetch.rs      bundle download and remote signature fetch
  initrd.rs     manifest embedding into initramfs CPIO
  paths.rs      bundle filename and version helpers
  stage.rs      tar ABI validation and staging
  transfer.rs   HTTP download and SHA-256 streaming helpers
  verify.rs     Ed25519 signature policy and verification

src/runtime/
  command.rs    process execution and stderr redaction
  config.rs     target network, crypttab, fstab, recovery, and GRUB config
  environment.rs RAM-boot and kernel-command-line guard
  install.rs    RAM installer orchestration
  layout.rs     partition, LUKS, LVM, filesystem command generation
  mod.rs        public runtime API and module wiring
  tests.rs      runtime unit tests

src/rootfs/
  mod.rs        rootfs init, import, validation, and packing
  tests.rs      rootfs unit tests
```

The CLI entry point remains in `src/main.rs`; the safety-critical policy and
command-generation primitives remain in library modules so they can be tested
without touching host disks.
