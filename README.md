# encvol

`encvol` reinstalls an amd64 Debian-compatible VPS onto an encrypted LUKS2/LVM
layout. It is destructive: keep provider-console access and the LUKS recovery
passphrase available while installing.

For the design, trust model, installer ABI, and test-harness details, see
[docs/how-it-works.md](docs/how-it-works.md).

## Requirements

- Rust on the development machine.
- `debootstrap`, GNU `tar`, and `zstd` when building rootfs artifacts.
- A release `encvol` binary, which contains its own RAM installer.
- An amd64 Debian-compatible rootfs archive and descriptor served over HTTPS.
- Reachable Tang server and pinned Tang thumbprint for Clevis network unlock.
- One-line OpenSSH public key for restricted initramfs recovery SSH on port 2222.
- A direct whole-disk `/dev/<disk>` target that may be erased.

## Build

Debug/test builds may omit the embedded installer:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build
```

Production release builds use the packaging script, which builds a bootstrap
binary, creates the installer bundle, then rebuilds the final binary with that
bundle embedded:

```sh
sudo scripts/package-release.sh --output dist/encvol
```

The release artifact is the raw executable at `dist/encvol`.

## Create A Rootfs

Create a new editable Debian workspace:

```sh
sudo encvol rootfs init \
  --release trixie \
  --root /srv/encvol/trixie-root \
  --mirror https://deb.debian.org/debian
```

Package the workspace:

```sh
sudo encvol rootfs pack \
  --root /srv/encvol/trixie-root \
  --output /srv/encvol/publish/trixie-root.tar.zst \
  --archive-url https://images.example/encvol/trixie-root.tar.zst \
  --format tar.zst
```

This writes the archive and descriptor:

```text
/srv/encvol/publish/trixie-root.tar.zst
/srv/encvol/publish/trixie-root.tar.json
```

Import an offline filesystem partition or mapped filesystem device:

```sh
sudo encvol rootfs import \
  --source /dev/mapper/vg-root \
  --output /srv/encvol/publish/imported-root.tar \
  --archive-url https://images.example/encvol/imported-root.tar \
  --format tar
```

## Customize In QEMU

Use the QEMU helper when you want to boot the rootfs, SSH into it, make normal
system changes, then export that filesystem for a VPS install:

```sh
sudo scripts/qemu-rootfs.sh init \
  --hostname trixie-vps \
  --user kizu \
  --ssh-key ~/.ssh/id_ed25519.pub
scripts/qemu-rootfs.sh start
ssh -p 2222 kizu@127.0.0.1
```

`init` prompts for the hostname, primary user, optional root password, optional
user password, and whether password SSH should be enabled in the customization
rootfs. SSH key login is always configured for root and the primary user.

Shut the guest down cleanly when customization is done:

```sh
sudo poweroff
```

Then pack the same guest filesystem as the rootfs artifact you will publish:

```sh
sudo scripts/qemu-rootfs.sh pack \
  --archive-url https://images.example/encvol/trixie-root.tar.zst \
  --output /srv/encvol/publish/trixie-root.tar.zst
```

Or use the combined flow: it boots the guest, waits for it to power off, then
packs the rootfs automatically:

```sh
sudo scripts/qemu-rootfs.sh customize \
  --archive-url https://images.example/encvol/trixie-root.tar.zst \
  --output /srv/encvol/publish/trixie-root.tar.zst
```

Upload both `/srv/encvol/publish/trixie-root.tar.zst` and
`/srv/encvol/publish/trixie-root.tar.json` to the HTTPS location in the
descriptor before running `encvol install` on the VPS.

## Preflight

Inspect the target host before installation:

```sh
sudo encvol preflight --disk /dev/vdb --pretty
```

Stop if preflight reports an unsupported handoff or missing network capture.

## Plan Install

Without `--execute`, `install` prints the installation plan and does not stage
or reboot into the embedded installer:

```sh
sudo encvol install \
  --disk /dev/vdb \
  --rootfs-descriptor https://images.example/encvol/trixie-root.tar.json \
  --tang-url https://tang.example \
  --tang-thumbprint 'PINNED_TANG_THUMBPRINT' \
  --recovery-authorized-key ./recovery.pub \
  --swap-mib 1024 \
  --confirm WIPE:/dev/vdb
```

Add `--data-volume` to allocate remaining free LVM extents to a separate data
volume.

## Execute Install

`--execute` stages the embedded installer, appends the generated manifest to
the initrd, and performs the selected one-time boot handoff. This is the
disk-changing path:

```sh
sudo encvol install \
  --disk /dev/vdb \
  --rootfs-descriptor https://images.example/encvol/trixie-root.tar.json \
  --tang-url https://tang.example \
  --tang-thumbprint 'PINNED_TANG_THUMBPRINT' \
  --recovery-authorized-key ./recovery.pub \
  --confirm WIPE:/dev/vdb \
  --execute
```

The installed system unlocks automatically through Clevis/Tang using the pinned
Tang thumbprint. Recovery unlock is restricted Dropbear SSH on port 2222 using
the supplied public key.

## Test

Run the normal Rust gate:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Run the local QEMU harness on the prepared development VM:

```sh
sudo tests/qemu/run.sh --suite all
```

Run one QEMU case:

```sh
sudo tests/qemu/run.sh --suite bios --case bios-tar-root-swap
```
