#!/usr/bin/env bash
# Runs the FUSE tests in a Linux container, from any machine with Docker: they mount a Safe for real
# through /dev/fuse. Its build output stays in a Docker volume.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" -e CARGO_TARGET_DIR=/target -e RUSTUP_TOOLCHAIN="$toolchain" \
  -v "$root:/src:ro" -v octapass-fuse-target:/target -v octapass-fuse-cargo:/usr/local/cargo/registry \
  -w /src "rust:$toolchain-slim" \
  sh -c 'apt-get update -qq && apt-get install -qq -y fuse3 >/dev/null && cargo test --locked -p octapass-files --features fuse --test fuse -- --test-threads=1'
