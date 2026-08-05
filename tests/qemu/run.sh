#!/usr/bin/env bash
# Disposable local QEMU test entry point. It has no host block-device option.
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
suite=all
case_name=
keep_artifacts=0

usage() {
    printf '%s\n' 'usage: sudo tests/qemu/run.sh --suite unit|integration|bios|uefi|all [--case NAME] [--keep-artifacts]'
}

while (($#)); do
    case $1 in
        --suite) suite=${2:?missing suite}; shift 2 ;;
        --case) case_name=${2:?missing case name}; shift 2 ;;
        --keep-artifacts) keep_artifacts=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$suite" in unit|integration|bios|uefi|all) ;; *) usage >&2; exit 2 ;; esac

artifact_base=${ENCVOL_QEMU_ARTIFACT_DIR:-/var/tmp/encvol-qemu}
mkdir -p "$artifact_base"
exec 9>"$artifact_base/.lock"
flock -n 9 || { printf '%s\n' 'another encvol QEMU run is active' >&2; exit 75; }
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
artifacts="$artifact_base/$run_id"
mkdir -p "$artifacts"/{serial,qemu,disks,guest,manifests}
printf '{"run_id":"%s","suite":"%s"}\n' "$run_id" "$suite" > "$artifacts/manifest.json"

bridge="encvol-br-${run_id##*-}"
namespace="encvol-ns-${run_id##*-}"
pids=()
cleanup() {
    status=$?
    for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    ip netns del "$namespace" 2>/dev/null || true
    ip link del "$bridge" 2>/dev/null || true
    # Fixture credentials are useful only while a guest is running.  Never
    # retain them with --keep-artifacts (which is for disks and diagnostics),
    # and do this on both success and failure paths.
    if [[ -d $artifacts/secrets ]]; then
        find "$artifacts/secrets" -depth -delete 2>/dev/null || true
    fi
    # Guest recipes maintain detailed per-case JUnit in results.xml.  Fast
    # suites still receive a compact result when no guest recipe ran.
    if [[ ! -e $artifacts/results.xml ]]; then
        printf '<testsuite name="encvol-qemu" tests="1" failures="%s"><testcase name="%s"/></testsuite>\n' "$((status != 0))" "$suite" > "$artifacts/results.xml"
    fi
    if ((status == 0 && keep_artifacts == 0)); then
        # Case runner stores every writable guest drive as an overlay below
        # cases/.  Logs and metadata remain, while no successful run leaves a
        # reusable guest disk behind.
        find "$artifacts/disks" "$artifacts/cases" -type f -name '*.qcow2' -delete 2>/dev/null || true
    fi
}
trap cleanup EXIT

run_fast() {
    run_cargo fmt --check
    run_cargo clippy --all-targets -- -D warnings
    run_cargo test
}

# The runner is normally invoked through sudo for TAP/bridge cleanup, but the
# Rust toolchain belongs to the login user, not root.
run_cargo() {
    if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        sudo -u "$SUDO_USER" -- env HOME="$user_home" PATH="$user_home/.cargo/bin:$PATH" cargo "$@"
    else
        cargo "$@"
    fi
}

require_qemu_host() {
    local missing=()
    for tool in qemu-system-x86_64 qemu-img debootstrap mkfs.ext4 mount umount tar \
                sha256sum openssl ssh-keygen gzip zstd cpio chroot ip flock python3 timeout jose; do
        command -v "$tool" >/dev/null || missing+=("$tool")
    done
    [[ -x /usr/libexec/tangd ]] || missing+=(/usr/libexec/tangd)
    [[ -x /usr/libexec/tangd-keygen ]] || missing+=(/usr/libexec/tangd-keygen)
    [[ -e /dev/kvm ]] || missing+=(/dev/kvm)
    ((${#missing[@]} == 0)) || { printf 'QEMU suite prerequisites missing: %s\n' "${missing[*]}" >&2; return 1; }
}

run_guest_suite() {
    require_qemu_host
    local case_args=()
    [[ -z $case_name ]] || case_args=(--case "$case_name")
    "$repo_root/tests/qemu/build-fixtures.sh" --artifacts "$artifacts" --suite "$1" "${case_args[@]}"
    "$repo_root/tests/qemu/run-case.sh" --artifacts "$artifacts" --suite "$1" "${case_args[@]}"
}

run_all_guest_suites() {
    require_qemu_host
    local case_args=()
    [[ -z $case_name ]] || case_args=(--case "$case_name")
    "$repo_root/tests/qemu/build-fixtures.sh" --artifacts "$artifacts" --suite all "${case_args[@]}"
    "$repo_root/tests/qemu/run-case.sh" --artifacts "$artifacts" --suite bios "${case_args[@]}"
    "$repo_root/tests/qemu/run-case.sh" --artifacts "$artifacts" --suite uefi "${case_args[@]}"
}

cd "$repo_root"
case "$suite" in
    unit) run_fast ;;
    integration) run_cargo test --test cli ;;
    bios|uefi) run_guest_suite "$suite" ;;
    all)
        run_fast
        run_all_guest_suites
        ;;
esac
printf 'artifacts: %s\n' "$artifacts"
