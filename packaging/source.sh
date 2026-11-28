#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
base=$(sed -n 's/^pkgver=//p' "$project_dir/packaging/PKGBUILD.in")
rev_count=$(git -C "$project_dir" rev-list --count HEAD)
short_sha=$(git -C "$project_dir" rev-parse --short=12 HEAD)
pkgver=${GITX_PKGVER:-"${base}.r${rev_count}.g${short_sha}"}
if [[ ! $pkgver =~ ^[0-9][[:alnum:]_.+]*$ ]]; then
  printf 'Invalid package version: %s\n' "$pkgver" >&2
  exit 1
fi
archive="$project_dir/packaging/gitx-source.tar.gz"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner \
  --transform='s,^,gitx/,' -C "$project_dir" -cf - \
  Cargo.toml Cargo.lock crates README.md LICENSE assets/icon.png |
  gzip -n > "$archive"
digest=$(sha256sum -- "$archive")
digest=${digest%% *}
sed -e "s/@SOURCE_SHA256@/$digest/" -e "s/^pkgver=.*/pkgver=$pkgver/" \
  "$project_dir/packaging/PKGBUILD.in" > "$project_dir/packaging/PKGBUILD"
(cd "$project_dir/packaging" && makepkg --printsrcinfo > .SRCINFO)
printf 'Generated %s, packaging/PKGBUILD, and packaging/.SRCINFO (pkgver=%s)\nSHA-256 %s\n' "$archive" "$pkgver" "$digest"
