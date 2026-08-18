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
guest_hostname=${ENCVOL_ROOTFS_HOSTNAME:-}
guest_user=${ENCVOL_ROOTFS_USER:-}
memory=${ENCVOL_ROOTFS_MEMORY_MB:-2048}
cpus=${ENCVOL_ROOTFS_CPUS:-2}
format=tar.zst
output=
archive_url=
root_password=
user_password=
password_ssh=0
force_stop=0
qemu_command=()
release_set=0

usage() {
    cat <<'EOF'
usage:
  sudo scripts/qemu-rootfs.sh init [options]
  scripts/qemu-rootfs.sh start [options]
  scripts/qemu-rootfs.sh stop [--force] [options]
  sudo scripts/qemu-rootfs.sh pack --archive-url URL [options]
  sudo scripts/qemu-rootfs.sh customize --archive-url URL [options]

options:
  --workdir DIR       State directory. Default: /srv/encvol/trixie-qemu
  --release NAME      Debian release. Default: trixie
  --mirror URL        Debian mirror. Default: https://deb.debian.org/debian
  --hostname NAME     Guest hostname. Default: encvol-RELEASE
  --user NAME         Primary login user. Default: encvol
  --ssh-key PATH      Public key installed for root and the primary user.
  --ssh-port PORT     Host SSH port forwarded to the guest. Default: 2222
  --disk-size SIZE    QEMU root disk size for init. Default: 12G
  --memory MB         QEMU memory for start. Default: 2048
  --cpus N            QEMU CPUs for start. Default: 2
  --output PATH       Rootfs archive path for pack.
  --archive-url URL   HTTPS URL where the archive will be published.
  --format FORMAT     tar or tar.zst for pack. Default: tar.zst
  --force             With stop, terminate the matching QEMU process.
EOF
}

while (($#)); do
    case $1 in
        --workdir) workdir=${2:?missing workdir}; shift 2 ;;
        --release) release=${2:?missing release}; release_set=1; shift 2 ;;
        --mirror) mirror=${2:?missing mirror}; shift 2 ;;
        --hostname) guest_hostname=${2:?missing hostname}; shift 2 ;;
        --user) guest_user=${2:?missing user}; shift 2 ;;
        --ssh-key) ssh_key=${2:?missing ssh key}; shift 2 ;;
        --ssh-port) ssh_port=${2:?missing ssh port}; shift 2 ;;
        --disk-size) disk_size=${2:?missing disk size}; shift 2 ;;
        --memory) memory=${2:?missing memory}; shift 2 ;;
        --cpus) cpus=${2:?missing cpu count}; shift 2 ;;
        --output) output=${2:?missing output path}; shift 2 ;;
        --archive-url) archive_url=${2:?missing archive URL}; shift 2 ;;
        --format) format=${2:?missing format}; shift 2 ;;
        --force) force_stop=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

disk="$workdir/rootfs.raw"
kernel="$workdir/vmlinuz"
initrd="$workdir/initrd.img"
state_file="$workdir/rootfs.env"
pidfile="$workdir/qemu.pid"

load_state() {
    [[ -r $state_file ]] || return 0
    local key value
    while IFS='=' read -r key value; do
        case $key in
            release) ((release_set)) || release=$value ;;
            hostname) [[ -n $guest_hostname ]] || guest_hostname=$value ;;
            user) [[ -n $guest_user ]] || guest_user=$value ;;
        esac
    done < "$state_file"
}

write_state() {
    cat > "$state_file" <<EOF
release=$release
hostname=$guest_hostname
user=$guest_user
EOF
}

load_state

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

valid_hostname() {
    [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
}

valid_user() {
    [[ $1 =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]
}

ask_default() {
    local prompt=$1 default=$2 answer=
    printf '%s [%s]: ' "$prompt" "$default" >&2
    read -r answer
    printf '%s\n' "${answer:-$default}"
}

ask_yes_no() {
    local prompt=$1 answer=
    printf '%s [y/N]: ' "$prompt" >&2
    read -r answer
    [[ $answer == y || $answer == Y || $answer == yes || $answer == YES ]]
}

ask_password_twice() {
    local label=$1 first= second=
    while true; do
        printf '%s password: ' "$label" >&2
        read -r -s first
        printf '\n' >&2
        printf 'Confirm %s password: ' "$label" >&2
        read -r -s second
        printf '\n' >&2
        [[ $first == "$second" ]] || {
            printf '%s\n' 'passwords did not match; try again' >&2
            continue
        }
        [[ $first != *:* ]] || {
            printf '%s\n' 'passwords cannot contain :' >&2
            continue
        }
        printf '%s\n' "$first"
        return
    done
}

collect_init_config() {
    if [[ -z $guest_hostname ]]; then
        if [[ -t 0 ]]; then
            guest_hostname=$(ask_default 'Hostname' "encvol-${release}")
        else
            guest_hostname="encvol-${release}"
        fi
    fi
    valid_hostname "$guest_hostname" || {
        printf 'invalid hostname: %s\n' "$guest_hostname" >&2
        exit 2
    }

    if [[ -z $guest_user ]]; then
        if [[ -t 0 ]]; then
            guest_user=$(ask_default 'Primary user' encvol)
        else
            guest_user=encvol
        fi
    fi
    valid_user "$guest_user" || {
        printf 'invalid user: %s\n' "$guest_user" >&2
        exit 2
    }
    [[ $guest_user != root ]] || {
        printf '%s\n' 'primary user must not be root; root is configured separately' >&2
        exit 2
    }

    if [[ -t 0 ]]; then
        if ask_yes_no 'Set a root password'; then
            root_password=$(ask_password_twice root)
        fi
        if ask_yes_no "Set a password for $guest_user"; then
            user_password=$(ask_password_twice "$guest_user")
        fi
        if [[ -n $root_password || -n $user_password ]]; then
            if ask_yes_no 'Allow password SSH login in this rootfs'; then
                password_ssh=1
            fi
        fi
    fi
}

set_chroot_password() {
    local user=$1 password=$2
    printf '%s:%s\n' "$user" "$password" | chroot "$mount_dir" /usr/sbin/chpasswd
}

init_rootfs() {
    require_root
    require_tools qemu-img debootstrap mkfs.ext4 mount umount install chroot find sort tail
    collect_init_config
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
    packages=systemd-sysv,linux-image-amd64,openssh-server,sudo,ca-certificates,curl,vim-tiny,iproute2,dbus,passwd
    debootstrap --arch=amd64 --include="$packages" "$release" "$mount_dir" "$mirror"

    printf '%s\n' "$guest_hostname" > "$mount_dir/etc/hostname"
    cat > "$mount_dir/etc/hosts" <<EOF
127.0.0.1 localhost
127.0.1.1 ${guest_hostname}
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
    if ((password_ssh)); then
        sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' \
            "$mount_dir/etc/ssh/sshd_config.d/90-encvol-qemu.conf"
    fi

    chroot "$mount_dir" /usr/sbin/groupadd -f "$guest_user"
    if ! chroot "$mount_dir" /usr/bin/id -u "$guest_user" >/dev/null 2>&1; then
        chroot "$mount_dir" /usr/sbin/useradd -m -g "$guest_user" -s /bin/bash "$guest_user"
    fi
    mkdir -p "$mount_dir/home/$guest_user/.ssh" "$mount_dir/etc/sudoers.d"
    install -m 0600 "$key" "$mount_dir/home/$guest_user/.ssh/authorized_keys"
    local guest_uid guest_gid
    guest_uid=$(chroot "$mount_dir" /usr/bin/id -u "$guest_user")
    guest_gid=$(chroot "$mount_dir" /usr/bin/id -g "$guest_user")
    chown -R "$guest_uid:$guest_gid" "$mount_dir/home/$guest_user/.ssh"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$guest_user" > "$mount_dir/etc/sudoers.d/$guest_user"
    chmod 0440 "$mount_dir/etc/sudoers.d/$guest_user"
    if [[ -n $root_password ]]; then
        set_chroot_password root "$root_password"
    fi
    if [[ -n $user_password ]]; then
        set_chroot_password "$guest_user" "$user_password"
    fi
    : > "$mount_dir/etc/machine-id"

    copy_boot_artifacts "$mount_dir"
    cleanup_mount
    mounted=
    write_state

    if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        chown -R "$SUDO_USER:${SUDO_GID:-$(id -g "$SUDO_USER")}" "$workdir"
    fi
    printf 'created %s\n' "$disk"
    printf 'boot it with: scripts/qemu-rootfs.sh start --workdir %q\n' "$workdir"
}

qemu_args() {
    require_tools qemu-system-x86_64
    [[ -r $disk && -r $kernel && -r $initrd ]] || {
        printf 'missing QEMU state in %s; run init first\n' "$workdir" >&2
        exit 2
    }
    local accel=()
    [[ -r /dev/kvm && -w /dev/kvm ]] && accel=(-enable-kvm)
    qemu_command=(
        qemu-system-x86_64
        "${accel[@]}"
        -m "$memory"
        -smp "$cpus"
        -pidfile "$pidfile"
        -drive "file=$disk,format=raw,if=virtio"
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
        -device virtio-net-pci,netdev=net0
        -kernel "$kernel"
        -initrd "$initrd"
        -append "root=/dev/vda rw console=ttyS0 systemd.unit=multi-user.target net.ifnames=0"
        -nographic
    )
}

run_qemu() {
    qemu_args
    printf 'SSH after boot: ssh -p %s %s@127.0.0.1\n' "$ssh_port" "$guest_user"
    if [[ ${EUID:-$(id -u)} -eq 0 && -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        sudo -u "$SUDO_USER" -- "${qemu_command[@]}"
    else
        "${qemu_command[@]}"
    fi
}

start_rootfs() {
    [[ -n $guest_user ]] || guest_user=encvol
    run_qemu
}

qemu_pids_for_disk() {
    local pid cmdline
    if [[ -r $pidfile ]]; then
        pid=$(<"$pidfile")
        if [[ $pid =~ ^[0-9]+$ && -r /proc/$pid/cmdline ]]; then
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
            if [[ $cmdline == *qemu-system-x86_64* && $cmdline == *"$disk"* ]]; then
                printf '%s\n' "$pid"
                return 0
            fi
        fi
    fi
    for path in /proc/[0-9]*/cmdline; do
        [[ -r $path ]] || continue
        cmdline=$(tr '\0' ' ' < "$path")
        [[ $cmdline == *qemu-system-x86_64* && $cmdline == *"$disk"* ]] || continue
        pid=${path#/proc/}
        printf '%s\n' "${pid%/cmdline}"
    done
}

force_stop_qemu() {
    local pids=()
    mapfile -t pids < <(qemu_pids_for_disk | sort -u)
    ((${#pids[@]} > 0)) || {
        printf 'no QEMU process found for %s\n' "$disk" >&2
        exit 1
    }
    kill "${pids[@]}"
    printf 'terminated QEMU pid(s): %s\n' "${pids[*]}"
    rm -f "$pidfile"
}

stop_rootfs() {
    [[ -n $guest_user ]] || guest_user=encvol
    if ((force_stop)); then
        force_stop_qemu
        return
    fi
    require_tools ssh
    if ssh \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=accept-new \
        -p "$ssh_port" \
        "$guest_user@127.0.0.1" \
        'sudo -n systemctl poweroff --no-wall >/dev/null 2>&1 &'
    then
        printf 'shutdown requested for QEMU rootfs at %s\n' "$workdir"
        return
    fi
    printf '%s\n' 'clean shutdown over SSH failed; use stop --force only if the guest is stuck' >&2
    exit 1
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

customize_rootfs() {
    require_root
    [[ -n $guest_user ]] || guest_user=encvol
    run_qemu
    printf '%s\n' 'guest exited; packing rootfs'
    pack_rootfs
}

case "$action" in
    init) init_rootfs ;;
    start) start_rootfs ;;
    stop) stop_rootfs ;;
    pack) pack_rootfs ;;
    customize) customize_rootfs ;;
    --help|-h|'') usage ;;
    *) usage >&2; exit 2 ;;
esac
