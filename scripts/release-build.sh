#!/usr/bin/env bash
# Builds the release binary, target/release/tsong, the way a release is
# built: locked dependencies, and the paths that differ between machines,
# this directory and the cargo home, remapped to fixed ones in the Rust
# code and in the C code of native dependencies. Two builds of the same
# commit are then identical, as scripts/reproducible.sh checks.
#
#   scripts/release-build.sh
set -euo pipefail

cd "$(dirname "$0")/.."
here="$(pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
RUSTFLAGS="--remap-path-prefix=$here=/build --remap-path-prefix=$cargo_home=/cargo" \
  CFLAGS="-ffile-prefix-map=$here=/build" \
  cargo build --release --locked -p tsong
