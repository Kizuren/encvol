#!/usr/bin/env bash
# Execute one or more disposable QEMU recipes.  This script deliberately only
# ever attaches qcow2 overlays: the fixture's source image and base target are
# evidence, never writable guests disks.
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
artifacts=
suite=
requested_case=
case_bridge=
case_tap=
https_pid=
tang_pid=

usage() {
    printf '%s\n' 'usage: run-case.sh --artifacts DIR --suite bios|uefi|faults [--case NAME]'
}

while (($#)); do
    case $1 in
        --artifacts) artifacts=${2:?missing artifact directory}; shift 2 ;;
        --suite) suite=${2:?missing suite}; shift 2 ;;
        --case) requested_case=${2:?missing case name}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ -n $artifacts && -n $suite ]] || { usage >&2; exit 2; }
case $suite in bios|uefi|faults) ;; *) usage >&2; exit 2 ;; esac

source_image="$artifacts/disks/source.raw"
kernel="$artifacts/qemu/source.kernel"
initrd="$artifacts/qemu/source.initrd"
target_base="$artifacts/disks/target.qcow2"
qemu_memory_mb=${ENCVOL_QEMU_MEMORY_MB:-4096}
[[ $qemu_memory_mb =~ ^[1-9][0-9]*$ ]] || {
    printf '%s\n' 'ENCVOL_QEMU_MEMORY_MB must be a positive integer' >&2
    exit 2
}
qemu_timeout_seconds=${ENCVOL_QEMU_TIMEOUT_SECONDS:-300}
[[ $qemu_timeout_seconds =~ ^[1-9][0-9]*$ ]] || {
    printf '%s\n' 'ENCVOL_QEMU_TIMEOUT_SECONDS must be a positive integer' >&2
    exit 2
}
for required in "$source_image" "$kernel" "$initrd" "$target_base"; do
    [[ -f $required ]] || { printf 'missing QEMU fixture: %s\n' "$required" >&2; exit 1; }
done

# A case is an observable supported behaviour, not an arbitrary collection of
# QEMU errors.  Keep names stable: they are used in artifact paths and JUnit.
bios_cases=(
    bios-tar-root-swap bios-tarzst-root-swap-data
    bios-live-root-rootdisk-free bios-live-root-secondary-free
    bios-live-root-secondary-shrink-ext4
    bios-live-root-mounted-target-refusal
    bios-live-root-secondary-final-xfs-refusal
)
uefi_cases=(
    uefi-tar-root-swap uefi-tarzst-root-swap-data
    uefi-live-root-rootdisk-free uefi-live-root-secondary-free
)
pre_faults=(
    missing-installer-flag non-ram-root invalid-target mounted-target
    invalid-confirmation rootfs-unavailable rootfs-wrong-hash
    rootfs-malformed-descriptor rootfs-malformed-archive rootfs-unsupported-format
    tang-unavailable missing-executable unsupported-handoff
)
post_faults=(
    wipefs partition luks-format luks-open pvcreate vgcreate lvcreate filesystem
    swap esp-format mount rootfs-extract target-config bind-mount chroot
    apt-metadata package-install clevis-bind initramfs grub-generate
    bootloader-install final-reboot
)
fault_cases=()
for fault in "${pre_faults[@]}"; do fault_cases+=("pre-${fault}"); done
for fault in "${post_faults[@]}"; do fault_cases+=("post-${fault}"); done

case_in_list() {
    local needle=$1 item
    shift
    for item; do [[ $item == "$needle" ]] && return 0; done
    return 1
}

case "$suite" in
    bios) cases=("${bios_cases[@]}") ;;
    uefi) cases=("${uefi_cases[@]}") ;;
    faults) cases=("${fault_cases[@]}") ;;
esac
if [[ -n $requested_case ]]; then
    case "$requested_case" in
        source-smoke)
            # A deliberately non-destructive fixture diagnostic.  It is never
            # selected by --suite all and cannot be confused with an install.
            cases=(source-smoke)
            ;;
        *)
            case_in_list "$requested_case" "${cases[@]}" || {
                printf 'case %q does not belong to suite %s\n' "$requested_case" "$suite" >&2
                exit 2
            }
            cases=("$requested_case")
            ;;
    esac
fi

mkdir -p "$artifacts"/{cases,junit}
source_hash_before=$(sha256sum "$source_image" | awk '{print $1}')
base_target_hash=$(sha256sum "$target_base" | awk '{print $1}')

network_value() {
    local key=$1 value
    value=$(awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' "$artifacts/network.env")
    [[ -n $value ]] || { printf 'missing %s in network fixture\n' "$key" >&2; return 1; }
    printf '%s' "$value"
}

setup_case_network() {
    local case_dir=$1 suffix gateway prefix
    gateway=$(network_value GATEWAY)
    prefix=$(network_value PREFIX)
    [[ $gateway =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ && $prefix =~ ^[0-9]{1,2}$ ]] || {
        printf '%s\n' 'fixture supplied an invalid private network address' >&2
        return 1
    }
    # Linux interface names are limited to 15 bytes.  The artifact basename
    # and shell PID keep simultaneously-invoked (direct) case runs separate.
    suffix=$(printf '%s' "${case_dir##*/}-$BASHPID" | sha256sum | cut -c1-7)
    case_bridge="evbr$suffix"
    case_tap="evtap$suffix"
    ip link add name "$case_bridge" type bridge
    ip addr add "$gateway/$prefix" dev "$case_bridge"
    ip link set "$case_bridge" up
    ip tuntap add dev "$case_tap" mode tap
    ip link set "$case_tap" master "$case_bridge"
    ip link set "$case_tap" up
    python3 "$repo_root/tests/qemu/serve-https.py" \
        --bind "$gateway" --root "$artifacts/services/https" \
        --cert "$artifacts/certs/server.crt" --key "$artifacts/certs/server.key" \
        > "$case_dir/qemu/https.log" 2>&1 &
    https_pid=$!
    systemd-socket-activate -l "${gateway}:8080" --accept --inetd \
        /usr/libexec/tangd "$artifacts/tang" \
        > "$case_dir/qemu/tang.log" 2>&1 &
    tang_pid=$!
    # A bind failure must be reported before the guest starts, not misread as
    # a rootfs validation fault.  The short check does not wait on a network.
    sleep 0.1
    kill -0 "$https_pid" 2>/dev/null || {
        printf '%s\n' 'private HTTPS fixture did not start' >&2
        return 1
    }
    kill -0 "$tang_pid" 2>/dev/null || {
        printf '%s\n' 'private Tang fixture did not start' >&2
        return 1
    }
}

cleanup_case_network() {
    [[ -n ${https_pid:-} ]] && kill "$https_pid" 2>/dev/null || true
    [[ -n ${https_pid:-} ]] && wait "$https_pid" 2>/dev/null || true
    [[ -n ${tang_pid:-} ]] && kill "$tang_pid" 2>/dev/null || true
    [[ -n ${tang_pid:-} ]] && wait "$tang_pid" 2>/dev/null || true
    [[ -n ${case_tap:-} ]] && ip link del "$case_tap" 2>/dev/null || true
    [[ -n ${case_bridge:-} ]] && ip link del "$case_bridge" 2>/dev/null || true
    https_pid=
    tang_pid=
    case_tap=
    case_bridge=
}
trap cleanup_case_network EXIT
trap 'cleanup_case_network; exit 130' INT
trap 'cleanup_case_network; exit 143' TERM

xml_escape() {
    local value=$1
    value=${value//&/&amp;}
    value=${value//</&lt;}
    value=${value//>/&gt;}
    value=${value//\"/&quot;}
    value=${value//\'/&apos;}
    printf '%s' "$value"
}

write_case_junit() {
    local name=$1 state=$2 duration=$3 detail=$4 out="$artifacts/junit/$name.xml"
    {
        printf '<testcase classname="encvol.qemu.%s" name="%s" time="%s">' \
            "$(xml_escape "$suite")" "$(xml_escape "$name")" "$duration"
        case $state in
            pass) ;;
            skip) printf '<skipped message="%s"/>' "$(xml_escape "$detail")" ;;
            # Logs remain in the case directory.  Keeping JUnit concise also
            # avoids copying arbitrary serial bytes into XML.
            *) printf '<failure message="%s"/>' "$(xml_escape "$detail")" ;;
        esac
        printf '</testcase>\n'
    } > "$out"
}

write_results() {
    local count failures skipped file
    count=$(find "$artifacts/junit" -maxdepth 1 -name '*.xml' -type f | wc -l | tr -d ' ')
    # Keep the runner usable on the deliberately lean Debian development VM;
    # this is reporting plumbing, so it must not require a developer's usual
    # search-tool installation.
    failures=$(grep -rl '<failure ' "$artifacts/junit" 2>/dev/null | wc -l | tr -d ' ' || true)
    skipped=$(grep -rl '<skipped ' "$artifacts/junit" 2>/dev/null | wc -l | tr -d ' ' || true)
    {
        printf '<testsuite name="encvol-qemu" tests="%s" failures="%s" skipped="%s">\n' "$count" "$failures" "$skipped"
        while IFS= read -r file; do cat "$file"; done < <(find "$artifacts/junit" -maxdepth 1 -name '*.xml' -type f | sort)
        printf '</testsuite>\n'
    } > "$artifacts/results.xml"
}

assert_no_secret_leak() {
    local case_dir=$1 secrets="$artifacts/guest/secret-values"
    [[ -f $secrets ]] || return 0
    local secret
    while IFS= read -r secret || [[ -n $secret ]]; do
        [[ -z $secret ]] && continue
        # Do not echo either the matched data or the secret on a failure.
        if grep -R -F -q --exclude='secret-values' -- "$secret" "$case_dir/serial" "$case_dir/qemu" "$case_dir/guest" "$case_dir/manifests" 2>/dev/null; then
            printf '%s\n' 'secret redaction assertion failed' >&2
            return 1
        fi
    done < "$secrets"
}

disk_relation() {
    # qemu-img compare checks virtual disk contents, avoiding qcow2 header
    # churn (dirty bits/allocation metadata) being misreported as a wipe.
    local overlay=$1
    qemu-img compare -q -f qcow2 -F qcow2 "$overlay" "$target_base"
}

source_disk_relation() {
    local overlay=$1
    qemu-img compare -q -f qcow2 -F raw "$overlay" "$source_image"
}

read_case_options() {
    # A builder may provide declarative options, one key=value per line:
    # expected_disk=changed|unchanged; expected_source_disk=changed|unchanged;
    # serial_contains=TEXT; qemu_args_file=PATH.
    # Only these keys are recognized, so test artifacts cannot affect shell.
    # Shell local assignments are expanded left-to-right before `case_name`
    # exists under `set -u`; assign it first so a fresh, option-less case is
    # a supported path rather than an unbound-variable failure.
    local case_name=$1
    local options="$artifacts/qemu/case-$case_name.expect" line key value
    expected_disk=
    expected_source_disk=
    required_serial=()
    extra_qemu_args=()
    [[ -f $options ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line || $line == \#* ]] && continue
        key=${line%%=*}; value=${line#*=}
        [[ $key != "$line" ]] || { printf 'invalid case option in %s\n' "$options" >&2; return 1; }
        case $key in
            expected_disk)
                case $value in changed|unchanged) expected_disk=$value ;; *) return 1 ;; esac
                ;;
            expected_source_disk)
                case $value in changed|unchanged) expected_source_disk=$value ;; *) return 1 ;; esac
                ;;
            serial_contains) required_serial+=("$value") ;;
            qemu_args_file)
                [[ $value != /* && $value != *'..'* ]] || return 1
                local args_file="$artifacts/qemu/$value"
                [[ -f $args_file ]] || return 1
                mapfile -t extra_qemu_args < "$args_file"
                ;;
            *) printf 'unknown case option %s\n' "$key" >&2; return 1 ;;
        esac
    done < "$options"
}

run_one_case() {
    local name=$1 case_dir="$artifacts/cases/$1" start end duration status detail
    local source_overlay="$case_dir/disks/source.qcow2" target_overlay="$case_dir/disks/target.qcow2"
    local serial="$case_dir/serial/console.log" qemu_log="$case_dir/qemu/qemu.log" monitor="$case_dir/qemu/monitor.log"
    local qemu_status=0 compare_status=0 source_compare_status=0 actual_source_disk=unverified
    case_bridge= case_tap= https_pid=
    local -a qemu_args append_args

    case $name in
        (*[!a-z0-9-]*|'') printf 'unsafe case name\n' >&2; return 2 ;;
    esac
    [[ ! -e $case_dir ]] || { printf 'case artifact directory already exists: %s\n' "$case_dir" >&2; return 1; }
    mkdir -p "$case_dir"/{disks,serial,qemu,guest,manifests}
    printf '%s\n' "$name" > "$case_dir/case-name"
    printf '%s\n' "$suite" > "$case_dir/suite"
    # The source image is immutable backing storage for its per-case overlay.
    # Hashing its multi-GiB bytes once below verifies that contract; repeating
    # it for every matrix cell needlessly dominates the suite's runtime.
    printf '%s  %s\n' "$source_hash_before" "$source_image" > "$case_dir/disks/source-base.sha256"
    sha256sum "$target_base" > "$case_dir/disks/target-base.sha256"
    qemu-img info --output=json "$target_base" > "$case_dir/disks/target-base-info.json"
    qemu-img create -q -f qcow2 -F raw -b "$source_image" "$source_overlay"
    qemu-img create -q -f qcow2 -F qcow2 -b "$target_base" "$target_overlay"
    qemu-img info --output=json "$source_overlay" > "$case_dir/disks/source-overlay-before.json"
    qemu-img info --output=json "$target_overlay" > "$case_dir/disks/target-overlay-before.json"

    read_case_options "$name"
    case $name in
        source-smoke) expected_disk=${expected_disk:-unchanged}; required_serial+=(encvol) ;;
        pre-*) expected_disk=${expected_disk:-unchanged}; required_serial+=("ENCVOL_FAULT:${name#pre-}") ;;
        post-*) expected_disk=${expected_disk:-changed}; required_serial+=("ENCVOL_FAULT:${name#post-}") ;;
        *live-root*refusal) expected_disk=${expected_disk:-changed} ;;
        *live-root*) expected_disk=${expected_disk:-changed}; required_serial+=('encvol: installer-run exited 0') ;;
        *) expected_disk=${expected_disk:-changed}; required_serial+=('encvol: installer-run exited 0') ;;
    esac
    if [[ $name == *tarzst-root-swap-data ]]; then
        required_serial+=('encvol: qemu rootfs format tar.zst' 'encvol: qemu data volume enabled' 'Logical volume "data" created.')
    elif [[ $name == *tar-root-swap ]]; then
        required_serial+=('encvol: qemu rootfs format tar')
    fi
    # The fixture can append non-network QEMU arguments in its declarative
    # file.  User-mode and host bridge networking are always forbidden.
    local arg
    for arg in "${extra_qemu_args[@]}"; do
        [[ $arg != *user* && $arg != *bridge* ]] || { printf 'unsafe QEMU network option\n' >&2; return 1; }
    done
    # dropbear-initramfs enables the initramfs network hook.  Supply the
    # fixture's deterministic address up front so a source boot cannot spend
    # its DHCP timeout waiting for a service this private bridge never runs.
    # The virtio NIC is eth0 while initramfs-tools configures it; systemd may
    # subsequently rename it to enp0s2 in the mounted system.
    append_args=(
        "root=/dev/vda1 rw console=ttyS0"
        "ip=192.168.231.2::192.168.231.1:255.255.255.0::eth0:off"
        "encvol.test_case=$name"
    )
    if [[ $name != source-smoke ]]; then
        append_args+=(encvol.qemu.source=1)
        [[ $suite == uefi ]] && append_args+=(encvol.qemu_firmware=uefi)
    fi
    [[ $name == pre-* || $name == post-* ]] && append_args+=("encvol.test_fault=${name#*-}")
    if ! setup_case_network "$case_dir"; then
        cleanup_case_network
        return 1
    fi
    qemu_args=(
        -enable-kvm -cpu host -machine q35,accel=kvm -m "$qemu_memory_mb" -smp 2 -nographic
        -kernel "$kernel" -initrd "$initrd" -append "${append_args[*]}"
        -drive "file=$source_overlay,format=qcow2,if=virtio" -drive "file=$target_overlay,format=qcow2,if=virtio"
        -serial "file:$serial" -monitor "file:$monitor" -d guest_errors -D "$qemu_log"
        -netdev "tap,id=encvolnet,ifname=$case_tap,script=no,downscript=no" -device virtio-net-pci,netdev=encvolnet
    )
    if [[ $suite == uefi ]]; then
        local ovmf_code=${ENCVOL_QEMU_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
        local ovmf_vars=${ENCVOL_QEMU_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
        [[ -r $ovmf_code && -r $ovmf_vars ]] || {
            printf 'OVMF firmware is required for UEFI cases\n' >&2
            cleanup_case_network
            return 1
        }
        cp "$ovmf_vars" "$case_dir/qemu/OVMF_VARS.fd"
        qemu_args+=( -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" -drive "if=pflash,format=raw,file=$case_dir/qemu/OVMF_VARS.fd" )
    fi
    qemu_args+=("${extra_qemu_args[@]}")
    printf '%q ' qemu-system-x86_64 "${qemu_args[@]}" > "$case_dir/qemu/command.txt"
    printf '\n' >> "$case_dir/qemu/command.txt"
    start=$(date +%s)
    if timeout --foreground "$qemu_timeout_seconds" qemu-system-x86_64 "${qemu_args[@]}" >> "$qemu_log" 2>&1; then
        :
    else
        qemu_status=$?
    fi
    cleanup_case_network
    end=$(date +%s); duration=$((end - start))
    printf '%s\n' "$qemu_status" > "$case_dir/qemu/exit-status"
    qemu-img info --output=json "$source_overlay" > "$case_dir/disks/source-overlay-after.json"
    qemu-img info --output=json "$target_overlay" > "$case_dir/disks/target-overlay-after.json"
    sha256sum "$target_overlay" > "$case_dir/disks/target-overlay.sha256"
    if disk_relation "$target_overlay"; then
        actual_disk=unchanged
    else
        compare_status=$?
        if [[ $compare_status == 1 ]]; then
            actual_disk=changed
        else
            printf 'qemu-img compare failed with status %s\n' "$compare_status" >&2
            actual_disk=unavailable
        fi
    fi
    if [[ -n $expected_source_disk ]]; then
        if source_disk_relation "$source_overlay"; then
            actual_source_disk=unchanged
        else
            source_compare_status=$?
            if [[ $source_compare_status == 1 ]]; then
                actual_source_disk=changed
            else
                printf 'source qemu-img compare failed with status %s\n' "$source_compare_status" >&2
                actual_source_disk=unavailable
            fi
        fi
        printf '%s\n' "$actual_source_disk" > "$case_dir/disks/source-virtual-state"
    fi
    printf '%s\n' "$actual_disk" > "$case_dir/disks/target-virtual-state"
    printf 'expected_disk=%s\nactual_disk=%s\nexpected_source_disk=%s\nactual_source_disk=%s\nqemu_exit=%s\n' \
        "$expected_disk" "$actual_disk" "$expected_source_disk" "$actual_source_disk" "$qemu_status" > "$case_dir/guest/outcome.env"

    status=pass; detail=ok
    if [[ $qemu_status -ne 0 ]]; then status=fail; detail="QEMU exited with status $qemu_status"; fi
    if [[ $actual_disk != "$expected_disk" ]]; then status=fail; detail="target virtual state is $actual_disk; expected $expected_disk"; fi
    if [[ -n $expected_source_disk && $actual_source_disk != "$expected_source_disk" ]]; then
        status=fail; detail="source virtual state is $actual_source_disk; expected $expected_source_disk"
    fi
    local marker
    for marker in "${required_serial[@]}"; do
        if ! grep -F -q -- "$marker" "$serial"; then
            status=fail; detail="serial log lacks required milestone for $name"
        fi
    done
    if ! assert_no_secret_leak "$case_dir"; then status=fail; detail='secret redaction assertion failed'; fi
    # A fixture-specific assertion is an executable owned by the repository
    # builder.  It receives only artifact paths, never recovery secrets.
    local assertion="$artifacts/guest/assert-$name.sh"
    if [[ -x $assertion ]] && ! ENCVOL_QEMU_CASE_DIR="$case_dir" ENCVOL_QEMU_CASE="$name" "$assertion"; then
        status=fail; detail='fixture case assertion failed'
    fi
    if [[ $status == pass ]]; then
        printf 'case %s passed: target %s\n' "$name" "$actual_disk" > "$case_dir/guest/assertions.txt"
    else
        printf 'case %s failed: %s\n' "$name" "$detail" > "$case_dir/guest/assertions.txt"
    fi
    write_case_junit "$name" "$status" "$duration" "$detail"
    write_results
    [[ $status == pass ]]
}

overall=0
for test_case in "${cases[@]}"; do
    if ! run_one_case "$test_case"; then overall=1; fi
done
source_hash_after=$(sha256sum "$source_image" | awk '{print $1}')
target_hash_after=$(sha256sum "$target_base" | awk '{print $1}')
printf 'source_before=%s\nsource_after=%s\ntarget_base_before=%s\ntarget_base_after=%s\n' \
    "$source_hash_before" "$source_hash_after" "$base_target_hash" "$target_hash_after" > "$artifacts/disks/base-integrity.env"
if [[ $source_hash_before != "$source_hash_after" || $base_target_hash != "$target_hash_after" ]]; then
    printf '%s\n' 'QEMU mutated a fixture base image; refusing to report success' >&2
    overall=1
fi
write_results
exit "$overall"
