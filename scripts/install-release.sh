#!/usr/bin/env sh
# Install encvol from GitHub Releases.
set -eu

repo=${ENCVOL_REPO:-Kizuren/encvol}
version=${ENCVOL_VERSION:-latest}
install_dir=${ENCVOL_INSTALL_DIR:-/usr/local/sbin}

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'install-release.sh must run as root; use sudo' >&2
    exit 77
fi

for tool in curl install mktemp sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing prerequisite: %s\n' "$tool" >&2
        exit 77
    }
done

case "$version" in
    latest) base_url="https://github.com/${repo}/releases/latest/download" ;;
    *) base_url="https://github.com/${repo}/releases/download/${version}" ;;
esac

tmp=$(mktemp -d)
cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

curl -fsSL "$base_url/encvol" -o "$tmp/encvol"
curl -fsSL "$base_url/encvol.sha256" -o "$tmp/encvol.sha256"

(cd "$tmp" && sha256sum -c encvol.sha256)
install -d -m 0755 "$install_dir"
install -m 0755 "$tmp/encvol" "$install_dir/encvol"

printf 'installed encvol to %s/encvol\n' "$install_dir"
"$install_dir/encvol" --version
