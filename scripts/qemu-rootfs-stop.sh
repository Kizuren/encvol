#!/usr/bin/env bash
# Convenience wrapper for stopping the local editable rootfs VM.
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "$repo_root/scripts/qemu-rootfs.sh" stop "$@"
