#!/usr/bin/env bash
# Builds the release binary twice, with scripts/release-build.sh, from two
# copies of the tree in different directories, and fails unless the two
# are identical bit for bit.
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
  CARGO_HOME="$cargo_home" "$dir/scripts/release-build.sh"
  sha256sum "$dir/target/release/tsong"
done

if cmp "$work/a/target/release/tsong" "$work/b/target/release/tsong"; then
  echo "the two builds are identical"
else
  echo "the two builds differ" >&2
  exit 1
fi
