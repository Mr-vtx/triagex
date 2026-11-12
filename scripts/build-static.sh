#!/usr/bin/env bash
# Build a fully static Triagex binary (musl) and prove it has no dynamic dependencies.
#
#   ./scripts/build-static.sh            # builds for this machine's architecture
#   ./scripts/build-static.sh aarch64    # needs a linker for that target (see README)
#   SKIP_BUILD=1 ./scripts/build-static.sh   # only re-check an existing binary
set -euo pipefail
cd "$(dirname "$0")/.."

arch="${1:-$(uname -m)}"
case "$arch" in
  x86_64|amd64)  target=x86_64-unknown-linux-musl ;;
  aarch64|arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

if [ "${SKIP_BUILD:-0}" != 1 ]; then
  command -v rustup >/dev/null && rustup target add "$target"
  cargo build --release --locked --target "$target" -p triagex-cli
fi

bin="target/$target/release/triagex"
echo
ls -lh "$bin" | awk '{print "size:    " $5}'
file "$bin" | sed 's/^[^:]*: /type:    /'
if ldd "$bin" 2>&1 | grep -q "=>"; then
  echo "FAIL: the binary depends on shared libraries:" >&2; ldd "$bin" >&2; exit 1
fi
echo "static:  yes (no shared libraries)"
"$bin" --version | sed 's/^/version: /'
echo
echo "binary:  $bin"
