#!/usr/bin/env bash
# Build all disposable inputs used by the QEMU recipes.  This script is
# intentionally the one place that is allowed to contact the Debian mirror:
# once it returns, guests use only the private bridge and files below
# $artifacts.  It never accepts a host block device as an input.
set -Eeuo pipefail

artifacts=
suite=
case_name=
while (($#)); do
    case $1 in
        --artifacts) artifacts=${2:?}; shift 2 ;;
        --suite) suite=${2:?}; shift 2 ;;
        --case) case_name=${2:?}; shift 2 ;;
        *) printf 'unknown fixture option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ -n $artifacts && -n $suite ]] || { printf '%s\n' 'missing --artifacts or --suite' >&2; exit 2; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || { printf '%s\n' 'fixture builder must run as root (the runner is invoked with sudo)' >&2; exit 77; }
case "$artifacts" in
    /|/tmp|/var|/var/tmp)
        printf 'refusing unsafe QEMU artifact directory: %s\n' "$artifacts" >&2
        exit 2
        ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
mirror=${ENCVOL_QEMU_DEBIAN_MIRROR:-http://deb.debian.org/debian}
release=${ENCVOL_QEMU_DEBIAN_RELEASE:-bookworm}
version=0.0.0-qemu
gateway=${ENCVOL_QEMU_GATEWAY:-192.168.231.1}
guest=${ENCVOL_QEMU_GUEST_IP:-192.168.231.2}

for tool in qemu-img debootstrap mkfs.ext4 mount umount tar sha256sum openssl ssh-keygen \
            gzip zstd cpio chroot jose; do
    command -v "$tool" >/dev/null || { printf 'missing fixture prerequisite: %s\n' "$tool" >&2; exit 77; }
done
[[ -x /usr/libexec/tangd && -x /usr/libexec/tangd-keygen ]] || {
    printf '%s\n' 'missing fixture prerequisite: /usr/libexec/tangd and /usr/libexec/tangd-keygen' >&2
    exit 77
}

for generated in apt certs disks guest manifests qemu rootfs secrets services source-root rootfs-root tang; do
    rm -rf -- "$artifacts/$generated"
done
mkdir -p "$artifacts"/{apt,certs,disks,guest,manifests,qemu,rootfs,secrets,services,source-root,rootfs-root,tang}
chmod 0700 "$artifacts/secrets"

run_cargo() {
    if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        sudo -u "$SUDO_USER" -- env HOME="$user_home" PATH="$user_home/.cargo/bin:$PATH" "$@"
    else
        "$@"
    fi
}

run_cargo env ENCVOL_BOOTSTRAP_WITHOUT_INSTALLER_BUNDLE=1 \
    cargo build --release --manifest-path "$repo_root/Cargo.toml"
install -D -m 0755 "$repo_root/target/release/encvol" "$artifacts/qemu/bootstrap-encvol"

# The recovery passphrase is generated for a runner that needs it, but is not
# put into a bundle, image, command line, manifest, log, or fixture metadata.
# Keep it private to root and let run-case remove it before reporting artifacts.
umask 077
openssl rand -base64 36 > "$artifacts/secrets/recovery-passphrase"
ssh-keygen -q -t ed25519 -N '' -f "$artifacts/secrets/recovery-key" -C encvol-qemu
install -m 0644 "$artifacts/secrets/recovery-key.pub" "$artifacts/guest/recovery-key.pub"
umask 022

# The HTTPS service certificate is deliberately per run.  A local CA is copied
# into both initramfs and rootfs, so no public CA or outbound guest access is
# needed.  The host service itself is started by run-case after the bridge
# exists, not here.  Keep CA and leaf roles separate: Rustls/webpki correctly
# rejects a leaf-only self-signed certificate as a trust anchor.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$artifacts/certs/ca.key" -out "$artifacts/certs/ca.crt" \
    -subj "/CN=encvol-qemu-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$artifacts/certs/server.key" -out "$artifacts/certs/server.csr" \
    -subj "/CN=encvol-qemu" \
    -addext "subjectAltName=IP:${gateway},DNS:encvol-qemu" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
openssl x509 -req -days 1 \
    -in "$artifacts/certs/server.csr" \
    -CA "$artifacts/certs/ca.crt" -CAkey "$artifacts/certs/ca.key" -CAcreateserial \
    -out "$artifacts/certs/server.crt" -copy_extensions copyall >/dev/null 2>&1
chmod 0600 "$artifacts/certs/ca.key" "$artifacts/certs/server.key"

packages='systemd-sysv,linux-image-amd64,iproute2,kexec-tools,cryptsetup,lvm2,gdisk,dosfstools,ca-certificates,apt,openssh-server,dropbear-initramfs,clevis,clevis-luks,clevis-initramfs,grub-pc,grub-efi-amd64,shim-signed,initramfs-tools,dpkg-dev,zstd'

rootfs_root="$artifacts/rootfs-root"
source_root="$artifacts/source-root"
mount_root=0
cleanup_mount() {
    if ((mount_root)); then umount "$source_root" 2>/dev/null || true; fi
}
trap cleanup_mount EXIT

# Build the rootfs first.  It contains every package the RAM installer asks
# apt for and a flat file: repository.  Therefore installer-time apt never
# uses the Debian mirror, even when a package has to be configured again.
debootstrap --arch=amd64 --include="$packages" "$release" "$rootfs_root" "$mirror"
install -D -m 0755 "$repo_root/target/release/encvol" "$rootfs_root/usr/local/bin/encvol"
install -D -m 0644 "$artifacts/certs/ca.crt" "$rootfs_root/usr/local/share/ca-certificates/encvol-qemu.crt"
chroot "$rootfs_root" update-ca-certificates >/dev/null

mkdir -p "$rootfs_root/opt/encvol-apt"
# Download the package artifacts directly instead of asking APT to reinstall
# mutually-exclusive bootloader choices in one rootfs. The packages themselves
# are already present from debootstrap; this flat repository is the offline
# source used should APT need to verify or reinstall one inside the target.
chroot "$rootfs_root" sh -ec '
  cd /opt/encvol-apt
  apt-get update
  apt-get download linux-image-amd64 grub-pc grub-efi-amd64 shim-signed cryptsetup lvm2 clevis clevis-luks clevis-initramfs dropbear-initramfs
'
if chroot "$rootfs_root" sh -c 'command -v dpkg-scanpackages >/dev/null'; then
    chroot "$rootfs_root" sh -c 'cd /opt/encvol-apt && dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz'
else
    # Debian apt accepts an empty flat repository.  This fallback remains
    # useful on minimal mirrors; packages were already installed in the rootfs.
    : > "$rootfs_root/opt/encvol-apt/Packages"
    gzip -9c "$rootfs_root/opt/encvol-apt/Packages" > "$rootfs_root/opt/encvol-apt/Packages.gz"
fi
mkdir -p "$rootfs_root/etc/apt/sources.list.d"
printf 'deb [trusted=yes] file:/opt/encvol-apt ./\n' > "$rootfs_root/etc/apt/sources.list"
rm -f "$rootfs_root/etc/apt/sources.list.d"/*.list

# A booted target needs a deterministic private address.  Source and final
# target both use the same network because they never run at the same time.
mkdir -p "$rootfs_root/etc/systemd/network"
printf '[Match]\nName=eth0 en*\n\n[Network]\nAddress=%s/24\nGateway=%s\nDNS=%s\n' "$guest" "$gateway" "$gateway" \
    > "$rootfs_root/etc/systemd/network/10-encvol-qemu.network"
ln -sf /lib/systemd/system/systemd-networkd.service "$rootfs_root/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
ln -sf /lib/systemd/system/ssh.service "$rootfs_root/etc/systemd/system/multi-user.target.wants/ssh.service" || true
rm -f "$rootfs_root/etc/ssh/ssh_host_"*key*

# Source disk is a separate raw ext4 image: vda is never handed to the
# installer and vdb is always a fresh qcow2 target.  The old paths are kept as
# a stable fixture contract for individual case scripts.
source_raw="$artifacts/disks/source.raw"
qemu-img create -f raw "$source_raw" 5G >/dev/null
mkfs.ext4 -q -F "$source_raw"
mount -o loop "$source_raw" "$source_root"
mount_root=1
tar --numeric-owner -C "$rootfs_root" -cf - . | tar --numeric-owner -C "$source_root" -xf -
install -D -m 0755 "$artifacts/qemu/bootstrap-encvol" "$source_root/usr/local/bin/encvol"
install -m 0644 "$artifacts/certs/ca.crt" "$source_root/usr/local/share/ca-certificates/encvol-qemu.crt"
install -D -m 0644 "$artifacts/guest/recovery-key.pub" "$source_root/root/encvol-recovery.pub"

# Build the RAM installer from a bootstrap encvol. installer-run does not need
# an embedded bundle; only the source-side install command does.
installer_root="$source_root"
mkdir -p "$installer_root/etc/initramfs-tools/hooks" "$installer_root/etc/initramfs-tools/scripts/local-top"
cat > "$installer_root/etc/initramfs-tools/hooks/encvol-qemu" <<'EOF'
#!/bin/sh
set -eu
PREREQ=''
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_optional_file() {
    [ ! -e "$1" ] || copy_file config "$1"
}
add_optional_module() {
    manual_add_modules "$1" || true
}
copy_exec /usr/local/bin/encvol
copy_exec /usr/bin/ip
copy_exec /usr/sbin/wipefs
copy_exec /usr/sbin/sgdisk
copy_exec /usr/sbin/cryptsetup
copy_exec /usr/sbin/modprobe
copy_exec /usr/sbin/pvcreate
copy_exec /usr/sbin/vgcreate
copy_exec /usr/sbin/lvcreate
# BusyBox's initramfs hook may install applet hardlinks before this hook runs.
# Replace them with the real e2fsprogs/util-linux binaries: the installer
# requires ext4 support, while BusyBox provides mke2fs but not the mkfs.ext4
# applet name used by the runtime command list.
rm -f "${DESTDIR}/usr/sbin/mke2fs" "${DESTDIR}/usr/sbin/mkfs.ext4" "${DESTDIR}/usr/sbin/mkswap"
copy_exec /usr/sbin/mke2fs /usr/sbin/mke2fs
ln -s mke2fs "${DESTDIR}/usr/sbin/mkfs.ext4"
copy_exec /usr/sbin/mkswap /usr/sbin/mkswap
# dosfstools' mkfs.fat has no additional runtime dependency in some Debian
# builds and `copy_exec` reports that as a non-zero optional-library result
# after it has copied the executable. Keep the copied binary and continue.
copy_exec /usr/sbin/mkfs.fat || true
rm -f "${DESTDIR}/usr/bin/mount" "${DESTDIR}/usr/bin/tar" "${DESTDIR}/usr/sbin/chroot"
copy_exec /usr/bin/mount /usr/bin/mount
copy_exec /usr/bin/tar /usr/bin/tar
copy_exec /usr/sbin/chroot /usr/sbin/chroot
copy_exec /usr/bin/clevis
copy_exec /usr/bin/clevis-luks-bind
copy_exec /usr/bin/clevis-luks-common-functions
copy_exec /usr/bin/clevis-encrypt-tang
copy_exec /usr/bin/clevis-decrypt
copy_exec /usr/bin/clevis-decrypt-tang
copy_exec /usr/bin/jose
copy_exec /usr/bin/curl
copy_exec /usr/bin/luksmeta
copy_exec /usr/bin/pwmake
copy_exec /usr/bin/awk
copy_exec /usr/bin/sed
copy_exec /usr/bin/grep
copy_exec /usr/bin/sort
copy_exec /usr/bin/tail
copy_exec /usr/bin/cat
copy_exec /usr/bin/mktemp
copy_exec /usr/bin/mkdir
copy_exec /usr/bin/rm
copy_exec /usr/bin/touch
copy_exec /usr/bin/chmod
copy_optional_file /etc/cracklib/cracklib.conf
copy_optional_file /etc/security/pwquality.conf
copy_file config /etc/passwd
copy_optional_file /var/cache/cracklib/cracklib_dict.hwm
copy_optional_file /var/cache/cracklib/cracklib_dict.pwd
copy_optional_file /var/cache/cracklib/cracklib_dict.pwi
[ ! -x /usr/bin/zstd ] || copy_exec /usr/bin/zstd
copy_exec /usr/bin/systemd-ask-password
copy_file config /etc/ssl/certs/ca-certificates.crt
add_optional_module dm-mod
add_optional_module dm-crypt
add_optional_module xts
add_optional_module aesni-intel
add_optional_module fat
add_optional_module vfat
add_optional_module nls_cp437
add_optional_module nls_ascii
add_optional_module nls_iso8859-1
EOF
chmod 0755 "$installer_root/etc/initramfs-tools/hooks/encvol-qemu"
cat > "$installer_root/etc/initramfs-tools/scripts/local-top/encvol-qemu" <<'EOF'
#!/bin/sh
# The manifest is appended as a cpio overlay by the normal client staging
# path.  This script deliberately does nothing without it, so the base bundle
# remains safely bootable for inspection.
case "$(cat /proc/cmdline 2>/dev/null)" in *encvol.installer=1*) ;; *) exit 0;; esac
[ -r /etc/encvol/manifest.json ] || exit 0
echo 'encvol: RAM installer guard active'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /target
modprobe dm-crypt 2>/dev/null || true
modprobe vfat 2>/dev/null || true
iface=$(for path in /sys/class/net/*; do
    [ "${path##*/}" = lo ] || { printf '%s' "${path##*/}"; break; }
done)
[ -n "$iface" ] || { echo 'encvol: no private NIC'; poweroff -f; }
ip link set "$iface" up
ip addr add 192.168.231.2/24 dev "$iface" 2>/dev/null || true
ip route replace default via 192.168.231.1 dev "$iface"
export ENCVOL_CONFIRM=WIPE:/dev/vdb
export ENCVOL_QEMU_RECOVERY_PASSPHRASE=encvol-qemu-recovery-passphrase
firmware=bios
case "$(cat /proc/cmdline 2>/dev/null)" in *encvol.qemu_firmware=uefi*) firmware=uefi;; esac
/usr/local/bin/encvol installer-run --manifest /etc/encvol/manifest.json --firmware "$firmware" --execute
status=$?
echo "encvol: installer-run exited ${status}"
sync
poweroff -f
EOF
chmod 0755 "$installer_root/etc/initramfs-tools/scripts/local-top/encvol-qemu"

# Rebuild a RAM-only installer initramfs.  The final installed system retains
# dropbear-initramfs and its restricted recovery configuration, but the
# disposable RAM installer does not expose a recovery SSH service.  Debian's
# Dropbear hook assumes a fuller userspace than this deliberately minimal
# image and otherwise loops attempting to run missing applets before switch-
# root.  Excluding it here leaves the installer guard as the sole RAM entry
# point and avoids putting an extra network login surface in test media.
dropbear_hook="$installer_root/usr/share/initramfs-tools/hooks/dropbear"
dropbear_script="$installer_root/usr/share/initramfs-tools/scripts/init-premount/dropbear"
dropbear_bottom="$installer_root/usr/share/initramfs-tools/scripts/init-bottom/dropbear"
mv "$dropbear_hook" "$dropbear_hook.encvol-disabled"
mv "$dropbear_script" "$dropbear_script.encvol-disabled"
mv "$dropbear_bottom" "$dropbear_bottom.encvol-disabled"
chmod 0644 "$dropbear_hook.encvol-disabled" "$dropbear_script.encvol-disabled" "$dropbear_bottom.encvol-disabled"
restore_dropbear() {
    chmod 0755 "$dropbear_hook.encvol-disabled" "$dropbear_script.encvol-disabled" "$dropbear_bottom.encvol-disabled" 2>/dev/null || true
    mv "$dropbear_hook.encvol-disabled" "$dropbear_hook" 2>/dev/null || true
    mv "$dropbear_script.encvol-disabled" "$dropbear_script" 2>/dev/null || true
    mv "$dropbear_bottom.encvol-disabled" "$dropbear_bottom" 2>/dev/null || true
}
trap 'restore_dropbear; cleanup_mount' EXIT
chroot "$installer_root" update-initramfs -u -k all
restore_dropbear
kernel=$(find "$installer_root/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort | tail -1)
initrd=$(find "$installer_root/boot" -maxdepth 1 -type f -name 'initrd.img-*' | sort | tail -1)
[[ -n $kernel && -n $initrd ]]
install -m 0644 "$kernel" "$artifacts/qemu/source.kernel"
install -m 0644 "$initrd" "$artifacts/qemu/source.initrd"
install -m 0644 "$kernel" "$artifacts/qemu/installer.kernel"
install -m 0644 "$initrd" "$artifacts/qemu/installer.initrd"

bundle_dir="$artifacts/guest/bundles"
mkdir -p "$bundle_dir"
embedded_bundle="$bundle_dir/encvol-installer-${version}.bundle"
tar -C "$artifacts/qemu" \
    --transform='s|installer.kernel|kernel|' --transform='s|installer.initrd|initrd|' \
    -cf "$embedded_bundle" installer.kernel installer.initrd

run_cargo env ENCVOL_INSTALLER_BUNDLE="$embedded_bundle" \
    cargo build --release --manifest-path "$repo_root/Cargo.toml"
install -D -m 0755 "$repo_root/target/release/encvol" "$artifacts/guest/encvol"
install -D -m 0755 "$repo_root/target/release/encvol" "$rootfs_root/usr/local/bin/encvol"
install -D -m 0755 "$repo_root/target/release/encvol" "$source_root/usr/local/bin/encvol"

# Package both accepted formats and write descriptors consumed by the client
# and directly by installer cases. Do not include transient host mountpoints.
tar --numeric-owner --xattrs --acls --sparse \
    --exclude=./dev --exclude=./proc --exclude=./sys --exclude=./run --exclude=./tmp \
    -C "$rootfs_root" -cf "$artifacts/rootfs/bookworm-root.tar" .
zstd -q -T0 -f "$artifacts/rootfs/bookworm-root.tar" -o "$artifacts/rootfs/bookworm-root.tar.zst"
for format in tar tar.zst; do
    archive="$artifacts/rootfs/bookworm-root.$format"
    digest=$(sha256sum "$archive" | awk '{print $1}')
    cat > "$artifacts/rootfs/bookworm-root.$format.json" <<EOF
{"schema_version":1,"archive_url":"https://${gateway}/rootfs/bookworm-root.${format}","sha256":"${digest}","release":"${release}","architecture":"amd64","provides":["systemd","apt","debian-package-compatibility"],"format":"${format}"}
EOF
done

# A source boot is inert unless the recipe explicitly adds
# encvol.qemu.source=1.  With that opt-in it exercises the public client path:
# download descriptor over the private HTTPS service, build a manifest, stage
# the embedded installer bundle, then request the normal kexec handoff. This is
# intentionally not a hidden direct installer call.
install -D -m 0755 /dev/stdin "$source_root/usr/local/lib/encvol-qemu-source-run" <<'EOF'
#!/bin/sh
set -eu
case "$(cat /proc/cmdline 2>/dev/null)" in
  *encvol.qemu.source=1*) ;;
  *) echo 'encvol: disposable source fixture ready'; poweroff -f; exit 0 ;;
esac
iface=$(for path in /sys/class/net/*; do
    [ "${path##*/}" = lo ] || { printf '%s' "${path##*/}"; break; }
done)
[ -n "$iface" ] || { echo 'encvol: source fixture has no private NIC'; poweroff -f; exit 1; }
ip link set "$iface" up
ip addr replace 192.168.231.2/24 dev "$iface" 2>/dev/null || ip addr add 192.168.231.2/24 dev "$iface"
ip route replace default via 192.168.231.1 dev "$iface"
thumbprint=$(cat /var/lib/encvol/qemu-tang-thumbprint)
case_name=default
for arg in $(cat /proc/cmdline 2>/dev/null); do
  case "$arg" in encvol.test_case=*) case_name=${arg#encvol.test_case=};; esac
done
rootfs_descriptor=bookworm-root.tar.json
data_args=
case "$case_name" in
  *tarzst-root-swap-data)
    rootfs_descriptor=bookworm-root.tar.zst.json
    data_args=--data-volume
    echo 'encvol: qemu rootfs format tar.zst'
    echo 'encvol: qemu data volume enabled'
    ;;
  *)
    echo 'encvol: qemu rootfs format tar'
    ;;
esac
echo 'encvol: invoking normal client install path'
export ENCVOL_QEMU_DIRECT_KEXEC=1
set +e
/usr/local/bin/encvol install \
  --disk /dev/vdb \
  --rootfs-descriptor "https://192.168.231.1/rootfs/${rootfs_descriptor}" \
  --tang-url http://192.168.231.1:8080 \
  --tang-thumbprint "$thumbprint" \
  --recovery-authorized-key /root/encvol-recovery.pub \
  --swap-mib 1024 \
  ${data_args} \
  --confirm WIPE:/dev/vdb \
  --execute
status=$?
echo "encvol: source client exited ${status}"
poweroff -f
exit "$status"
EOF
mkdir -p "$source_root/etc/systemd/system/multi-user.target.wants"
cat > "$source_root/etc/systemd/system/encvol-qemu-source.service" <<'EOF'
[Unit]
Description=encvol disposable source fixture
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/encvol-qemu-source-run
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF
ln -sf ../encvol-qemu-source.service "$source_root/etc/systemd/system/multi-user.target.wants/encvol-qemu-source.service"

# No target is ever derived from the source.  Its before-hash is the oracle
# used by pre-destructive fault recipes.
qemu-img create -f qcow2 "$artifacts/disks/target.qcow2" 16G >/dev/null
sha256sum "$artifacts/disks/target.qcow2" > "$artifacts/disks/target.before.sha256"

# Service roots are copied rather than served from a workspace path.  run-case
# binds both HTTPS and Tang only to the private bridge; Tang's signing-key
# thumbprint is recorded so Clevis can verify the advertisement without an
# interactive trust prompt.
mkdir -p "$artifacts/services/https/rootfs"
cp "$artifacts/rootfs"/bookworm-root.* "$artifacts/services/https/rootfs/"
/usr/libexec/tangd-keygen "$artifacts/tang" >/dev/null
for key in "$artifacts/tang"/*.jwk; do
    if jose fmt -j "$key" -Og key_ops -o- 2>/dev/null | grep -q '"verify"'; then
        jose jwk thp -i "$key" -a S256 > "$artifacts/tang/thumbprint"
        break
    fi
done
[[ -s $artifacts/tang/thumbprint ]] || { printf '%s\n' 'failed to derive Tang signing thumbprint' >&2; exit 1; }
printf '%s\n' "GATEWAY=$gateway" "GUEST_IP=$guest" "PREFIX=24" "BUNDLE_VERSION=$version" \
    "TANG_THUMBPRINT=$(tr -d '\n' < "$artifacts/tang/thumbprint")" > "$artifacts/network.env"
thumbprint=$(tr -d '\n' < "$artifacts/tang/thumbprint")
mkdir -p "$source_root/var/lib/encvol"
printf '%s\n' "$thumbprint" > "$source_root/var/lib/encvol/qemu-tang-thumbprint"
for format in tar tar.zst; do
    cp "$artifacts/rootfs/bookworm-root.$format.json" "$artifacts/manifests/rootfs-$format.json"
    data_volume=false
    [[ $format == tar.zst ]] && data_volume=true
    cat > "$artifacts/manifests/installer-$format.json" <<EOF
{"schema_version":1,"target_disk":"/dev/vdb","rootfs":$(<"$artifacts/rootfs/bookworm-root.$format.json"),"tang_url":"http://${gateway}:8080","tang_thumbprint":"${thumbprint}","recovery_authorized_key":"$(<"$artifacts/guest/recovery-key.pub")","network":{"interface":"eth0","mac_address":null,"mode":"static","addresses":["${guest}/24"],"gateway":"${gateway}","dns":["${gateway}"]},"layout":{"swap_mib":1024,"data_volume":${data_volume}}}
EOF
done
case_json=null
if [[ -n $case_name ]]; then case_json=$(printf '"%s"' "$case_name"); fi
cat > "$artifacts/fixtures.json" <<EOF
{"suite":"${suite}","case":${case_json},"source_disk":"disks/source.raw","target_disk":"disks/target.qcow2","installer_kernel":"qemu/installer.kernel","installer_initrd":"qemu/installer.initrd","https_root":"services/https","rootfs_formats":["tar","tar.zst"],"local_apt":"rootfs-root/opt/encvol-apt","tang_thumbprint":"${thumbprint}"}
EOF

umount "$source_root"
mount_root=0
rmdir "$source_root"
printf '%s\n' "$suite" > "$artifacts/fixture-suite"
