#!/usr/bin/env bash
# Builds the release binary twice, from two copies of the tree in different
# directories, and fails unless the two are identical bit for bit. Paths
# that differ between builds, the source directory and the cargo home, are
# remapped to fixed ones, in the Rust code and in the C code of native
# dependencies, so they don't reach the binary.
#
#   scripts/reproducible.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for copy in a b; do
  dir="$work/$copy"
  mkdir -p "$dir"
  git -C "$repo" archive HEAD | tar -x -C "$dir"
  (
    cd "$dir"
    RUSTFLAGS="--remap-path-prefix=$dir=/build --remap-path-prefix=$cargo_home=/cargo" \
      CFLAGS="-ffile-prefix-map=$dir=/build" \
      cargo build --release --locked -p tsong
  )
  sha256sum "$dir/target/release/tsong"
done

if cmp "$work/a/target/release/tsong" "$work/b/target/release/tsong"; then
  echo "the two builds are identical"
else
  echo "the two builds differ" >&2
  exit 1
fi
