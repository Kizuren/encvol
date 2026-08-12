# encvol

`encvol` reinstalls an amd64 VPS onto an encrypted LUKS2/LVM layout. It first creates a reviewable plan, then—only with an exact typed confirmation—stages a RAM-resident installer for a one-time boot. The installer verifies the rootfs archive before it changes the target disk.

This is an administrative, destructive tool. Keep provider-console access and the LUKS recovery passphrase available throughout the installation.

## What you need

- An amd64 Debian-compatible root filesystem.
- An HTTPS location for the rootfs archive and descriptor.
- An `encvol-installer-VERSION.bundle` in the bundle directory. For signature verification, also provide its detached `.sig` and the signer public key. Rootfs packaging does not create this separate installer bundle.
- A reachable Tang server and its pinned thumbprint.
- A one-line OpenSSH public key for initramfs recovery access.
- A machine where the selected whole disk can be erased.

The rootfs descriptor and the installation manifest are intentionally different. The descriptor is portable artifact metadata; `install` downloads it and combines it locally with the target disk, network, Tang pin, recovery key, and layout.

## Build and check the project

On a development machine with Rust installed:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

The complete on-demand local test entry point is:

```sh
sudo tests/qemu/run.sh --suite all
```

It only creates throwaway qcow2 disks and an isolated local guest network.
See [tests/qemu/README.md](tests/qemu/README.md) for prerequisites, artifact
locations, explicit cleanup behaviour, and single-case execution.

The release binary is `target/release/encvol`. A static installer binary, when the target is available, can be built with:

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

## Create a rootfs artifact

### Scenario: new editable Debian workspace

Run this on a build host. `init` requires an empty workspace and calls `debootstrap` for amd64 with `apt` and `systemd-sysv` included.

```sh
sudo target/release/encvol rootfs init \
  --release bookworm \
  --root /srv/encvol/bookworm-root \
  --mirror https://deb.debian.org/debian

# Make any required application and OS changes below this directory.
sudo target/release/encvol rootfs pack \
  --root /srv/encvol/bookworm-root \
  --output /srv/encvol/publish/bookworm-root.tar.zst \
  --archive-url https://images.example/encvol/bookworm-root.tar.zst \
  --format tar.zst
```

`pack` checks for `/usr/lib/systemd/systemd`, `apt`, Debian package metadata, and the Debian codename in `/etc/os-release`. It writes:

```text
/srv/encvol/publish/bookworm-root.tar.zst
/srv/encvol/publish/bookworm-root.tar.json
```

Upload both files unchanged to the HTTPS URLs used by the descriptor. The archive preserves numeric ownership, ACLs, xattrs, and sparse-file extents. Transient contents below `dev`, `proc`, `sys`, `run`, and `tmp` are excluded, while their empty mountpoint directories remain.

### Scenario: import an existing root filesystem

Use an offline filesystem or an externally-created storage snapshot; a read-only mount does not make a live filesystem consistent. `import` accepts a partition such as `/dev/vda2` or a mapped filesystem block device such as `/dev/mapper/vg-root`, never a whole disk or a raw disk image.

```sh
sudo target/release/encvol rootfs import \
  --source /dev/mapper/vg-root \
  --output /srv/encvol/publish/imported-root.tar \
  --archive-url https://images.example/encvol/imported-root.tar \
  --format tar
```

The source is mounted read-only on a private temporary mountpoint, then uses the same validation and packing path as `rootfs pack`.

## Inspect a target before installation

Always start with preflight. It does not write to the host.

```sh
sudo target/release/encvol preflight --disk /dev/vdb --pretty
```

The output identifies the usable handoff (`kexec`, UEFI BootNext, or GRUB) and reports the captured network configuration. Stop if it reports an unsupported handoff or cannot determine the network configuration.

## Produce an installation plan

The following command is non-destructive because it has no `--execute`. It downloads and validates the rootfs descriptor, captures network data, and prints the plan.

```sh
sudo target/release/encvol install \
  --disk /dev/vdb \
  --rootfs-descriptor https://images.example/encvol/bookworm-root.tar.json \
  --tang-url https://tang.example \
  --tang-thumbprint 'PINNED_TANG_THUMBPRINT' \
  --recovery-authorized-key ./recovery.pub \
  --swap-mib 1024 \
  --bundle-version 1.0.0 \
  --confirm WIPE:/dev/vdb
```

Add `--data-volume` when a separate LVM data volume is wanted. The default layout uses all non-swap LVM space for the root volume.

## Installer Bundle Trust

`encvol` does not compile in, publish, or pin an installer signing key. Each
operator owns their installer bundle and, if they want signature verification,
supplies the matching Ed25519 public key at verification time. The approved
signed fixture in `tests/fixtures/` proves signature verification in the test
suite. It is not an EFI executable and must never be used to boot a VM.

Verify a published local release before staging it:

```sh
target/release/encvol bundle verify --version VERSION \
  --directory /var/lib/encvol/releases \
  --signature /var/lib/encvol/releases/encvol-installer-VERSION.bundle.sig \
  --public-key RAW_ED25519_PUBLIC_KEY_HEX
```

Generate an operator signing key on the release host only. The private key is
encrypted, root-owned, mode `0600`, and is never copied into this repository:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/encvol-release
sudo openssl genpkey -algorithm ED25519 -aes-256-cbc \
  -out /var/lib/encvol-release/signing-key.pem
sudo chmod 0600 /var/lib/encvol-release/signing-key.pem
sudo openssl pkey -in /var/lib/encvol-release/signing-key.pem \
  -pubout -outform DER | tail -c 32 | xxd -p -c 256
```

Record that last value as the public key hex to pass to `--public-key` or
`--bundle-public-key`; then sign the exact bundle bytes interactively (the
command prompts for the key passphrase):

```sh
sudo openssl pkeyutl -sign \
  -inkey /var/lib/encvol-release/signing-key.pem -rawin \
  -in encvol-installer-VERSION.bundle | base64 -w 0 \
  > encvol-installer-VERSION.bundle.sig
target/release/encvol bundle verify --version VERSION --directory . \
  --signature encvol-installer-VERSION.bundle.sig \
  --public-key RAW_ED25519_PUBLIC_KEY_HEX
```

The detached signature is standard base64 text over the exact, unmodified
bundle bytes. Do not copy the encrypted key to a build worker or substitute an
environment variable, command-line option, or non-interactive passphrase for
the prompt.

For rotation, publish and test a release under the new key, distribute the new
public key through your own operational channel, and retain the prior key only
for the defined transition window. Never put a passphrase, private key, derived
key, or recovery secret in shell history, repository files, test artifacts, or
logs.

Installer bundle signatures are optional but recommended. `install`, `bundle
verify`, and `bundle fetch` warn when no signature is supplied. A signature is
provided explicitly with `--bundle-signature` and `--bundle-public-key` for
`install`, `--signature` and `--public-key` for `bundle verify`, or
`--signature-url` and `--public-key` for `bundle fetch`. Tar and boot-component
validation is always enforced, even without signature material.

## Local QEMU runbook

Run BIOS and UEFI QEMU testing only on the prepared development VM with nested
KVM. It must never be an installation target. The harness uses fresh qcow2
disks, a private TAP/bridge subnet and local fixture services; it does not use
external test VMs, a development-LAN attachment, or Debian network downloads
while a case runs. SeaBIOS covers BIOS and OVMF covers UEFI.

## Execute an installation

`--execute` is the final, disk-changing step. It stages the installer bundle
and reboots once into RAM; the RAM installer repeats the safety and rootfs
checksum checks before wiping the disk. Pass `--bundle-signature` and
`--bundle-public-key` to authenticate the bundle before staging it.

```sh
sudo target/release/encvol install \
  --disk /dev/vdb \
  --rootfs-descriptor https://images.example/encvol/bookworm-root.tar.json \
  --tang-url https://tang.example \
  --tang-thumbprint 'PINNED_TANG_THUMBPRINT' \
  --recovery-authorized-key ./recovery.pub \
  --bundle-version 1.0.0 \
  --bundle-signature /var/lib/encvol/releases/encvol-installer-1.0.0.bundle.sig \
  --bundle-public-key RAW_ED25519_PUBLIC_KEY_HEX \
  --confirm WIPE:/dev/vdb \
  --execute
```

Never automate the typed confirmation with a broad shell script. The target must be a direct whole-disk `/dev/<disk>` path; partitions, mapper devices, loop devices, and mounted targets are refused for installation.

## Installer-bundle ABI

A release consists of `encvol-installer-VERSION.bundle` and should publish a
detached-base64 Ed25519 signature for explicit client verification with the
operator-supplied public key. The bundle may contain only regular files named
`kernel`, `initrd`, and `installer.efi`; `kernel` and `initrd` must occur
together. An EFI fallback additionally needs `installer.efi`. The initramfs
must invoke:

```text
encvol installer-run --manifest /etc/encvol/manifest.json
```

No private key, recovery passphrase, LUKS key, GitHub token, or Tang secret belongs in the installer bundle, rootfs archive, descriptor, or repository.
