#!/usr/bin/env bash
# Build one Linux amd64 encvol binary with its installer bundle embedded.
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output="$repo_root/dist/encvol"
artifacts=
keep_artifacts=0

usage() {
    printf '%s\n' 'usage: sudo scripts/package-release.sh [--output PATH] [--artifacts DIR] [--keep-artifacts]'
}

while (($#)); do
    case $1 in
        --output) output=${2:?missing output path}; shift 2 ;;
        --artifacts) artifacts=${2:?missing artifact directory}; shift 2 ;;
        --keep-artifacts) keep_artifacts=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
    printf '%s\n' 'release packaging must run as root because it builds Debian/QEMU installer fixtures' >&2
    exit 77
}

cleanup_artifacts=0
if [[ -z $artifacts ]]; then
    artifacts=$(mktemp -d /var/tmp/encvol-release.XXXXXX)
    cleanup_artifacts=1
fi
chmod 0755 "$artifacts"

cleanup() {
    local status=$?
    if ((cleanup_artifacts && keep_artifacts == 0 && status == 0)); then
        rm -rf -- "$artifacts"
    fi
}
trap cleanup EXIT

"$repo_root/tests/qemu/build-fixtures.sh" --artifacts "$artifacts" --suite release
install -D -m 0755 "$artifacts/guest/encvol" "$output"
printf 'release binary: %s\n' "$output"
