#!/usr/bin/env bash
# Make a disposable boot initramfs from the reusable unsigned test bundle.
# The manifest is inserted into the initrd CPIO stream, exactly like
# bundle::embed_manifest; the bundle itself remains immutable and contains no
# machine-specific configuration.
set -Eeuo pipefail

artifacts=
format=tar
while (($#)); do
    case $1 in
        --artifacts) artifacts=${2:?}; shift 2 ;;
        --format) format=${2:?}; shift 2 ;;
        *) printf 'unknown staging option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ -n $artifacts ]] || { printf '%s\n' 'missing --artifacts' >&2; exit 2; }
case $format in tar|tar.zst) ;; *) printf '%s\n' 'format must be tar or tar.zst' >&2; exit 2;; esac

base="$artifacts/qemu/installer.initrd"
manifest="$artifacts/manifests/installer-$format.json"
output="$artifacts/qemu/installer-$format.initrd"
[[ -f $base && -f $manifest ]] || { printf '%s\n' 'fixture input is missing' >&2; exit 1; }
overlay=$(mktemp -d "$artifacts/qemu/overlay.XXXXXX")
cleanup() { rm -rf "$overlay"; }
trap cleanup EXIT
mkdir -p "$overlay/etc/encvol"
install -m 0600 "$manifest" "$overlay/etc/encvol/manifest.json"
(cd "$overlay" && find . -print | cpio -o -H newc --quiet) > "$overlay/manifest.cpio"
zstd -dc "$base" > "$overlay/base.cpio"
python3 - "$overlay/base.cpio" "$overlay/manifest.cpio" "$overlay/combined.cpio" <<'PY'
import pathlib
import sys

base = pathlib.Path(sys.argv[1]).read_bytes()
overlay = pathlib.Path(sys.argv[2]).read_bytes()

def align4(value):
    return (value + 3) & ~3

def parse_hex(data, offset):
    return int(data[offset:offset + 8].decode("ascii"), 16)

offset = 0
base_trailer = None
while offset + 110 <= len(base):
    magic = base[offset:offset + 6]
    if magic not in (b"070701", b"070702"):
        if base[offset:offset + 1] == b"\0":
            offset += 1
            continue
        break
    filesize = parse_hex(base, offset + 54)
    namesize = parse_hex(base, offset + 94)
    name_start = offset + 110
    name_end = name_start + namesize
    if namesize == 0 or name_end > len(base):
        break
    name = base[name_start:name_end - 1]
    if name == b"TRAILER!!!":
        base_trailer = offset
        break
    data_start = align4(name_end)
    data_end = data_start + filesize
    if data_end > len(base):
        break
    offset = align4(data_end)

if base_trailer is None:
    raise SystemExit("installer initrd has no readable newc trailer")

offset = 0
overlay_trailer = None
while offset + 110 <= len(overlay):
    magic = overlay[offset:offset + 6]
    if magic not in (b"070701", b"070702"):
        raise SystemExit("manifest overlay is not a readable newc archive")
    filesize = parse_hex(overlay, offset + 54)
    namesize = parse_hex(overlay, offset + 94)
    name_start = offset + 110
    name_end = name_start + namesize
    if namesize == 0 or name_end > len(overlay):
        raise SystemExit("manifest overlay is malformed")
    name = overlay[name_start:name_end - 1]
    if name == b"TRAILER!!!":
        overlay_trailer = offset
        break
    data_start = align4(name_end)
    data_end = data_start + filesize
    if data_end > len(overlay):
        raise SystemExit("manifest overlay is malformed")
    offset = align4(data_end)

if overlay_trailer is None:
    raise SystemExit("manifest overlay has no newc trailer")

overlay_entries = overlay[:overlay_trailer]
pathlib.Path(sys.argv[3]).write_bytes(
    base[:base_trailer] + overlay_entries + base[base_trailer:]
)
PY
zstd -q -c "$overlay/combined.cpio" > "$output"
printf '%s\n' "$output"
