# Local QEMU tests

Run the on-demand suite on the prepared development VM only:

```sh
sudo tests/qemu/run.sh --suite all
```

The runner takes an exclusive lock, creates one directory below
`/var/tmp/encvol-qemu`, and writes serial/QEMU logs, disk hashes, manifests,
fixture metadata, guest assertions, and `results.xml` there.  Use
`--keep-artifacts` to keep successful qcow2 disks, or `--case NAME` to select
one reproducible BIOS or UEFI recipe.

The harness defaults to `ENCVOL_QEMU_MEMORY_MB=4096` and
`ENCVOL_QEMU_TIMEOUT_SECONDS=300`.  The uncompressed tar rootfs is verified in
RAM before the target disk is wiped, so lower memory settings may fail valid
tar cases with initramfs `No space left on device`.  UEFI recipes can take
longer than BIOS because GRUB and shim trigger extra target initramfs and EFI
work; use the timeout variable for slower hosts.

## Prerequisites

The host needs KVM (`/dev/kvm`), QEMU, OVMF for UEFI recipes, `debootstrap`,
`qemu-img`, `iproute2`, `openssl`, `zstd`, `cpio`, `jose`, Tang's
`tangd`/`tangd-keygen` utilities, and a Debian mirror while fixtures are being
built.  Guests have no development-LAN or user-mode NIC, and do not contact
Debian after the builder completes.

## Fixture contract

`build-fixtures.sh` is intentionally reusable by individual case scripts. It
always creates these paths:

- `disks/source.raw` — a disposable Debian source system (vda).
- `disks/target.qcow2` — the only guest-writable installation target (vdb).
- `qemu/source.kernel` and `qemu/source.initrd` — source-system boot inputs.
- `qemu/installer.kernel` and `qemu/installer.initrd` — RAM-installer boot
  inputs. `stage-manifest.sh --artifacts DIR --format tar|tar.zst` creates a
  disposable initrd with the selected manifest appended as a newc overlay.
- `guest/bundles/encvol-installer-0.0.0-qemu.bundle` — the generated installer
  bundle embedded into the final source-side `encvol` binary.
- `guest/encvol` — the final release-mode binary with that bundle embedded.
- `rootfs/bookworm-root.tar` and `.tar.zst`, with matching descriptors and
  SHA-256 values; each rootfs contains an in-image flat local APT repository.
- `services/https` and `certs/` — a per-run TLS service root and certificate.
  Start `serve-https.py` only after binding its address to the private bridge.
- `manifests/installer-{tar,tar.zst}.json`, recovery public key, and
  `fixtures.json` metadata.

The source image has an opt-in systemd service.  Boot it with
`encvol.qemu.source=1` to exercise the public `encvol install --execute`
path with the embedded installer bundle and kexec handoff.  A plain source boot
emits `encvol: disposable source fixture ready` and powers off, which is useful
for a non-destructive source-image check.

The builder makes a per-run recovery passphrase only in the root-only
`secrets/` directory. It is never placed in an image, installer bundle,
manifest, command line, serial log, or final artifact report.  A case needing
to supply it must use an ephemeral guest channel and remove the secret before
the run is reported.  The harness removes private networking and temporary
service state on exit; it only preserves logs and disk copies when requested.

The builder creates per-run Tang keys and records the signing-key thumbprint
in `network.env`.  Each case starts a private Tang service bound only to the
fixture bridge, so success recipes exercise the real Clevis/Tang bind path
without using an external Tang service.
