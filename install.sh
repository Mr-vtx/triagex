#!/usr/bin/env sh
# Install Triagex: download the release for this machine, verify its checksum, install it.
#
#   curl -fsSL https://raw.githubusercontent.com/Mr-vtx/triagex/main/install.sh | sh
#
# Options (environment variables):
#   TRIAGEX_VERSION   release tag to install, e.g. v0.1.0 (default: the latest release)
#   INSTALL_DIR       where to put the binary (default: /usr/local/bin if writable, else ~/.local/bin)
#   TRIAGEX_BASE_URL  download from somewhere else (a mirror, or a local directory for testing)
#
# What it does, in full: detect the CPU, download one .tar.gz and SHA256SUMS, refuse to
# continue unless the checksum matches, copy one file into INSTALL_DIR, run `triagex --version`.
# It does not use sudo, change your PATH, or touch anything else.
set -eu

REPO="Mr-vtx/triagex"
say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "Triagex supports Linux only (found $(uname -s))"
case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) die "unsupported CPU: $(uname -m) (supported: x86_64, aarch64)" ;;
esac

fetch() { # URL DEST
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  else die "need curl or wget"; fi
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "need sha256sum or shasum to verify the download"; fi
}

tag="${TRIAGEX_VERSION:-}"
if [ -z "$tag" ]; then
  tmp_json="$(mktemp)"
  fetch "https://api.github.com/repos/$REPO/releases/latest" "$tmp_json" || die "could not look up the latest release"
  tag="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp_json" | head -n1)"
  rm -f "$tmp_json"
  [ -n "$tag" ] || die "could not read the latest release tag"
fi
case "$tag" in v[0-9]*) ;; *) die "unexpected version tag" ;; esac
case "$tag" in *[!A-Za-z0-9._-]*) die "unexpected characters in the version tag" ;; esac

base="${TRIAGEX_BASE_URL:-https://github.com/$REPO/releases/download/$tag}"
name="triagex-${tag}-${arch}-linux"

if [ -n "${INSTALL_DIR:-}" ]; then dest="$INSTALL_DIR"
elif [ -w /usr/local/bin ]; then dest=/usr/local/bin
else dest="$HOME/.local/bin"; fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say "Installing Triagex $tag for $arch-linux"
fetch "$base/$name.tar.gz" "$work/$name.tar.gz" || die "download failed: $base/$name.tar.gz"
fetch "$base/SHA256SUMS" "$work/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

expected="$(grep " $name.tar.gz\$" "$work/SHA256SUMS" | cut -d' ' -f1 | head -n1)"
[ -n "$expected" ] || die "no checksum listed for $name.tar.gz"
actual="$(sha256_of "$work/$name.tar.gz")"
[ "$expected" = "$actual" ] || die "CHECKSUM MISMATCH, refusing to install (expected $expected, got $actual)"
say "Checksum verified."

tar -xzf "$work/$name.tar.gz" -C "$work"
[ -f "$work/$name/triagex" ] || die "the archive does not contain a triagex binary"
mkdir -p "$dest"
cp "$work/$name/triagex" "$dest/triagex.new"
chmod 755 "$dest/triagex.new"
mv -f "$dest/triagex.new" "$dest/triagex"

say "Installed: $dest/triagex"
"$dest/triagex" --version
case ":$PATH:" in *":$dest:"*) ;; *) say "Note: $dest is not on your PATH." ;; esac
