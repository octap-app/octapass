#!/usr/bin/env bash
# The full local stack: octapass-server in dev mode on :8080 with a throwaway data directory, and
# the web vault on :5174 using the real WASM core. Ctrl-C stops both and deletes the data.
#
#   pnpm --filter @octapass/web dev:stack
#
# OCTAPASS_DATA_DIR=./somewhere keeps the data between runs instead.
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$root"

# Rebuilds the WASM core only when the Rust sources changed since its last build.
pnpm --filter @octapass/core build:if-stale
cargo build -p octapass-server

if [[ -n "${OCTAPASS_DATA_DIR:-}" ]]; then
  data_dir="$OCTAPASS_DATA_DIR"
  keep_data=1
  mkdir -p "$data_dir"
else
  data_dir="$(mktemp -d -t octapass-dev)"
  keep_data=0
fi

OCTAPASS_DEV_MODE=true \
OCTAPASS_DATA_DIR="$data_dir" \
OCTAPASS_BIND=127.0.0.1:8080 \
OCTAPASS_WEB_ORIGINS=http://localhost:5174 \
  target/debug/octapass-server &
server=$!
cleanup() {
  kill "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
  if [[ $keep_data == 0 ]]; then rm -rf "$data_dir"; fi
}
trap cleanup EXIT

echo "octapass-server: http://localhost:8080 (data in $data_dir; verification codes appear in the sign-up form)"
VITE_VAULT_BACKEND=remote pnpm --filter @octapass/web dev
