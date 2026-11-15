#!/usr/bin/env bash
# Runs a cargo command for the Linux target, in a podman container with the
# repository mounted. Tsong runs on Linux, so mutation testing runs there.
#
#   scripts/linux.sh test --workspace --locked
#   scripts/linux.sh mutants --workspace
#
# Named volumes keep the toolchain, the cargo registry and the build output
# between runs, apart from the Windows target directory.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -W 2>/dev/null || pwd)"

# cargo-mutants builds each parallel job in its own copy of the tree, so it
# keeps the build output there; a shared target directory would let the
# jobs overwrite each other's test binaries.
target=(-e CARGO_TARGET_DIR=/target)
if [ "${1:-}" = mutants ]; then
  target=()
fi

"$(dirname "$0")/podman.sh"
MSYS_NO_PATHCONV=1 exec podman run --rm \
  -v "$repo:/work" \
  -v tsong-cargo:/usr/local/cargo/registry \
  -v tsong-rustup:/usr/local/rustup \
  -v tsong-target:/target \
  -v tsong-tools:/tools \
  -e PATH=/tools/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  "${target[@]}" \
  -e RUSTFLAGS="${RUSTFLAGS:--D warnings}" \
  -w /work \
  docker.io/library/rust:1 \
  cargo "$@"
