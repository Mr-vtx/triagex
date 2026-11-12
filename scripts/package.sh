#!/usr/bin/env sh
# Package a built binary into a release archive, deterministically.
#
#   scripts/package.sh <tag> <arch> <path-to-binary> [outdir]
#   scripts/package.sh v0.1.0 x86_64 target/x86_64-unknown-linux-musl/release/triagex
#
# Produces  <outdir>/triagex-<tag>-<arch>-linux.tar.gz  containing the binary, LICENSE and
# README.md, with fixed timestamps and owners so the same input gives the same archive.
set -eu
[ $# -ge 3 ] || { echo "usage: $0 <tag> <arch> <binary> [outdir]" >&2; exit 2; }
tag="$1"; arch="$2"; bin="$3"; out="${4:-dist}"
[ -x "$bin" ] || { echo "not an executable file: $bin" >&2; exit 1; }

name="triagex-${tag}-${arch}-linux"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name" "$out"
cp "$bin" "$stage/$name/triagex"
chmod 755 "$stage/$name/triagex"
for f in LICENSE README.md; do [ -f "$f" ] && cp "$f" "$stage/$name/"; done

tar --sort=name --mtime='UTC 2026-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$stage" -cf - "$name" | gzip -9n > "$out/$name.tar.gz"
( cd "$out" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )
echo "$out/$name.tar.gz"
