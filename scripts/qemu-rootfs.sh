#!/usr/bin/env bash
# Build, boot, and export an editable Debian rootfs through local QEMU.
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
action=${1:-}
[[ -n $action ]] && shift || true

workdir=${ENCVOL_ROOTFS_WORKDIR:-/srv/encvol/trixie-qemu}
release=${ENCVOL_ROOTFS_RELEASE:-trixie}
mirror=${ENCVOL_ROOTFS_MIRROR:-https://deb.debian.org/debian}
disk_size=${ENCVOL_ROOTFS_DISK_SIZE:-12G}
ssh_port=${ENCVOL_ROOTFS_SSH_PORT:-2222}
ssh_key=${ENCVOL_ROOTFS_SSH_KEY:-}
memory=${ENCVOL_ROOTFS_MEMORY_MB:-2048}
cpus=${ENCVOL_ROOTFS_CPUS:-2}
format=tar.zst
output=
archive_url=

usage() {
    cat <<'EOF'
usage:
  sudo scripts/qemu-rootfs.sh init [options]
  scripts/qemu-rootfs.sh start [options]
  sudo scripts/qemu-rootfs.sh pack --archive-url URL [options]

options:
  --workdir DIR       State directory. Default: /srv/encvol/trixie-qemu
  --release NAME      Debian release. Default: trixie
  --mirror URL        Debian mirror. Default: https://deb.debian.org/debian
  --ssh-key PATH      Public key installed for root and encvol SSH.
  --ssh-port PORT     Host SSH port forwarded to the guest. Default: 2222
  --disk-size SIZE    QEMU root disk size for init. Default: 12G
  --memory MB         QEMU memory for start. Default: 2048
  --cpus N            QEMU CPUs for start. Default: 2
  --output PATH       Rootfs archive path for pack.
  --archive-url URL   HTTPS URL where the archive will be published.
  --format FORMAT     tar or tar.zst for pack. Default: tar.zst
EOF
}

while (($#)); do
    case $1 in
        --workdir) workdir=${2:?missing workdir}; shift 2 ;;
        --release) release=${2:?missing release}; shift 2 ;;
        --mirror) mirror=${2:?missing mirror}; shift 2 ;;
        --ssh-key) ssh_key=${2:?missing ssh key}; shift 2 ;;
        --ssh-port) ssh_port=${2:?missing ssh port}; shift 2 ;;
        --disk-size) disk_size=${2:?missing disk size}; shift 2 ;;
        --memory) memory=${2:?missing memory}; shift 2 ;;
        --cpus) cpus=${2:?missing cpu count}; shift 2 ;;
        --output) output=${2:?missing output path}; shift 2 ;;
        --archive-url) archive_url=${2:?missing archive URL}; shift 2 ;;
        --format) format=${2:?missing format}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

disk="$workdir/rootfs.raw"
kernel="$workdir/vmlinuz"
initrd="$workdir/initrd.img"

default_ssh_key() {
    if [[ -n $ssh_key ]]; then
        printf '%s\n' "$ssh_key"
        return
    fi
    if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        printf '%s\n' "$user_home/.ssh/id_ed25519.pub"
    else
        printf '%s\n' "$HOME/.ssh/id_ed25519.pub"
    fi
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || {
        printf '%s\n' "$action must run as root" >&2
        exit 77
    }
}

require_tools() {
    local missing=()
    for tool in "$@"; do
        command -v "$tool" >/dev/null || missing+=("$tool")
    done
    ((${#missing[@]} == 0)) || {
        printf 'missing prerequisites: %s\n' "${missing[*]}" >&2
        exit 77
    }
}

run_cargo() {
    if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        sudo -u "$SUDO_USER" -- env HOME="$user_home" PATH="$user_home/.cargo/bin:$PATH" "$@"
    else
        "$@"
    fi
}

encvol_bin() {
    if [[ -n ${ENCVOL_BIN:-} ]]; then
        [[ -x $ENCVOL_BIN ]] || {
            printf 'ENCVOL_BIN is not executable: %s\n' "$ENCVOL_BIN" >&2
            exit 2
        }
        printf '%s\n' "$ENCVOL_BIN"
        return
    fi
    if [[ ! -x $repo_root/target/debug/encvol ]]; then
        run_cargo cargo build --manifest-path "$repo_root/Cargo.toml"
    fi
    printf '%s\n' "$repo_root/target/debug/encvol"
}

mounted=
mount_dir=
cleanup_mount() {
    if [[ -n ${mounted:-} ]]; then
        umount "$mount_dir" 2>/dev/null || true
    fi
    if [[ -n ${mount_dir:-} ]]; then
        rmdir "$mount_dir" 2>/dev/null || true
    fi
}
trap cleanup_mount EXIT

mount_disk() {
    local mode=$1
    mount_dir=$(mktemp -d /tmp/encvol-rootfs.XXXXXX)
    mount -o "loop,$mode" "$disk" "$mount_dir"
    mounted=1
}

copy_boot_artifacts() {
    local root=$1
    local source_kernel source_initrd
    source_kernel=$(find "$root/boot" -maxdepth 1 -name 'vmlinuz-*' | sort -V | tail -n 1)
    source_initrd=$(find "$root/boot" -maxdepth 1 -name 'initrd.img-*' | sort -V | tail -n 1)
    [[ -n $source_kernel && -n $source_initrd ]] || {
        printf '%s\n' 'could not find Debian kernel/initrd in rootfs' >&2
        exit 1
    }
    install -m 0644 "$source_kernel" "$kernel"
    install -m 0644 "$source_initrd" "$initrd"
}

init_rootfs() {
    require_root
    require_tools qemu-img debootstrap mkfs.ext4 mount umount install chroot find sort tail
    local key
    key=$(default_ssh_key)
    [[ -r $key ]] || {
        printf 'SSH public key not found: %s\n' "$key" >&2
        exit 2
    }
    mkdir -p "$workdir"
    [[ ! -e $disk ]] || {
        printf 'refusing to overwrite existing disk: %s\n' "$disk" >&2
        exit 2
    }

    qemu-img create -f raw "$disk" "$disk_size" >/dev/null
    mkfs.ext4 -q -F -L encvol-root "$disk"
    mount_disk rw

    local packages
    packages=systemd-sysv,linux-image-amd64,openssh-server,sudo,ca-certificates,curl,vim-tiny,iproute2,dbus
    debootstrap --arch=amd64 --include="$packages" "$release" "$mount_dir" "$mirror"

    printf 'encvol-%s\n' "$release" > "$mount_dir/etc/hostname"
    cat > "$mount_dir/etc/hosts" <<EOF
127.0.0.1 localhost
127.0.1.1 encvol-${release}
EOF
    cat > "$mount_dir/etc/fstab" <<'EOF'
/dev/vda / ext4 defaults 0 1
EOF
    mkdir -p "$mount_dir/etc/systemd/network" "$mount_dir/etc/systemd/system/multi-user.target.wants"
    cat > "$mount_dir/etc/systemd/network/10-qemu.network" <<'EOF'
[Match]
Name=eth0 en*

[Network]
DHCP=yes
EOF
    ln -sf /lib/systemd/system/systemd-networkd.service \
        "$mount_dir/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
    ln -sf /lib/systemd/system/ssh.service \
        "$mount_dir/etc/systemd/system/multi-user.target.wants/ssh.service"

    mkdir -p "$mount_dir/root/.ssh" "$mount_dir/etc/ssh/sshd_config.d"
    install -m 0600 "$key" "$mount_dir/root/.ssh/authorized_keys"
    cat > "$mount_dir/etc/ssh/sshd_config.d/90-encvol-qemu.conf" <<'EOF'
PasswordAuthentication no
PermitRootLogin prohibit-password
EOF

    chroot "$mount_dir" useradd -m -s /bin/bash encvol 2>/dev/null || true
    mkdir -p "$mount_dir/home/encvol/.ssh" "$mount_dir/etc/sudoers.d"
    install -m 0600 "$key" "$mount_dir/home/encvol/.ssh/authorized_keys"
    chroot "$mount_dir" chown -R encvol:encvol /home/encvol/.ssh
    printf 'encvol ALL=(ALL) NOPASSWD:ALL\n' > "$mount_dir/etc/sudoers.d/encvol"
    chmod 0440 "$mount_dir/etc/sudoers.d/encvol"
    : > "$mount_dir/etc/machine-id"

    copy_boot_artifacts "$mount_dir"
    cleanup_mount
    mounted=

    if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        chown -R "$SUDO_USER:${SUDO_GID:-$(id -g "$SUDO_USER")}" "$workdir"
    fi
    printf 'created %s\n' "$disk"
    printf 'boot it with: scripts/qemu-rootfs.sh start --workdir %q\n' "$workdir"
}

start_rootfs() {
    require_tools qemu-system-x86_64
    [[ -r $disk && -r $kernel && -r $initrd ]] || {
        printf 'missing QEMU state in %s; run init first\n' "$workdir" >&2
        exit 2
    }
    local accel=()
    [[ -r /dev/kvm && -w /dev/kvm ]] && accel=(-enable-kvm)
    local args=(
        qemu-system-x86_64
        "${accel[@]}"
        -m "$memory"
        -smp "$cpus"
        -drive "file=$disk,format=raw,if=virtio"
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
        -device virtio-net-pci,netdev=net0
        -kernel "$kernel"
        -initrd "$initrd"
        -append "root=/dev/vda rw console=ttyS0 systemd.unit=multi-user.target net.ifnames=0"
        -nographic
    )
    printf 'SSH after boot: ssh -p %s encvol@127.0.0.1\n' "$ssh_port"
    if [[ ${EUID:-$(id -u)} -eq 0 && -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        exec sudo -u "$SUDO_USER" -- "${args[@]}"
    fi
    exec "${args[@]}"
}

pack_rootfs() {
    require_root
    require_tools mount umount find sort tail
    [[ -r $disk ]] || {
        printf 'missing QEMU disk in %s; run init first\n' "$workdir" >&2
        exit 2
    }
    [[ -n $archive_url ]] || {
        printf '%s\n' 'pack requires --archive-url with the final HTTPS archive URL' >&2
        exit 2
    }
    [[ $format == tar || $format == tar.zst ]] || {
        printf '%s\n' '--format must be tar or tar.zst' >&2
        exit 2
    }
    if [[ -z $output ]]; then
        output="$workdir/publish/${release}-root.${format}"
    fi
    mkdir -p "$(dirname -- "$output")"
    mount_disk ro
    "$(encvol_bin)" rootfs pack \
        --root "$mount_dir" \
        --output "$output" \
        --archive-url "$archive_url" \
        --format "$format"
    printf 'rootfs archive: %s\n' "$output"
}

case "$action" in
    init) init_rootfs ;;
    start) start_rootfs ;;
    pack) pack_rootfs ;;
    --help|-h|'') usage ;;
    *) usage >&2; exit 2 ;;
esac
