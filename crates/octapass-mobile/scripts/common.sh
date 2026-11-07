# Shared by the build and test scripts in this directory. Source it, don't run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SWIFT_PACKAGE="$ROOT/apps/ios/Packages/OctaPassVault"
KOTLIN_PROJECT="$ROOT/apps/android/vault"
SWIFT_SOURCE="$SWIFT_PACKAGE/Sources/OctaPassVault/OctaPassVault.swift"
KOTLIN_SOURCE="$KOTLIN_PROJECT/src/main/kotlin/app/octapass/vault/octapass_mobile.kt"
TARGET="$ROOT/target"
WORK="$TARGET/octapass-mobile"

# uniffi-bindgen gets its own target directory, so building it doesn't change the features the
# library is built with.
bindgen() {
  cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p octapass-mobile --features bindgen \
    --target-dir "$TARGET/uniffi-bindgen" --bin "$@"
}

# Swift source, C header and module map for the library $1, into directory $2. Only this
# crate's API: the library also holds octapass-ffi's, which the AutoFill extension gets from
# its own package.
generate_swift() {
  rm -rf "$2"
  bindgen uniffi-bindgen-swift -- "$1" "$2" --swift-sources --headers --modulemap \
    --module-name OctaPassVaultFFI --modulemap-filename module.modulemap \
    --metadata-no-deps
}

# Kotlin source for the library $1, into directory $2 (package app.octap.vault).
generate_kotlin() {
  rm -rf "$2"
  bindgen uniffi-bindgen -- generate --library "$1" --crate octapass_mobile --language kotlin \
    --no-format --out-dir "$2" --metadata-no-deps
}

# An XCFramework at $1 from static libraries ($2 …) and the headers in $HEADERS.
create_xcframework() {
  local output="$1" args=()
  shift
  for library in "$@"; do
    args+=(-library "$library" -headers "$HEADERS")
  done
  rm -rf "$output"
  xcodebuild -create-xcframework "${args[@]}" -output "$output" >/dev/null
}

# Fails when the committed bindings $1 differ from freshly generated ones $2.
check_bindings() {
  if ! diff -q "$1" "$2" >/dev/null; then
    echo "$1 is out of date: run crates/octapass-mobile/scripts/build-ios.sh and build-android.sh" >&2
    diff -u "$1" "$2" | head -40 >&2
    exit 1
  fi
}

# Starts the real sync server in development mode (no email, no rate limits) on a free port,
# with an empty database, and sets OCTAPASS_TEST_SERVER. A running one can be used instead by
# setting OCTAPASS_TEST_SERVER first. The server stops when the script exits.
start_dev_server() {
  if [[ -n "${OCTAPASS_TEST_SERVER:-}" ]]; then
    return
  fi
  cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p octapass-server
  local port data
  port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  data="$(mktemp -d)"
  OCTAPASS_BIND="127.0.0.1:$port" OCTAPASS_DEV_MODE=true OCTAPASS_RATE_LIMITS=off \
    OCTAPASS_DATA_DIR="$data" "$TARGET/debug/octapass-server" >"$data/server.log" 2>&1 &
  local pid=$!
  trap "kill $pid 2>/dev/null; rm -rf '$data'" EXIT
  export OCTAPASS_TEST_SERVER="http://127.0.0.1:$port"
  for _ in $(seq 1 100); do
    if curl -sf "$OCTAPASS_TEST_SERVER/v1/server-info" >/dev/null; then
      return
    fi
    sleep 0.2
  done
  cat "$data/server.log" >&2
  echo "the development server didn't start" >&2
  exit 1
}

# The C header and module map for this crate only, from the generated directory $1 into $2. They
# go in a folder of their own: an app that also links octapass-ffi's XCFramework (the AutoFill
# extension's) would otherwise get two include/module.modulemap files.
swift_headers() {
  rm -rf "$2" && mkdir -p "$2/OctaPassVaultFFI"
  cp "$1/OctaPassVaultFFI.h" "$2/OctaPassVaultFFI/"
  printf 'module OctaPassVaultFFI {\n    header "OctaPassVaultFFI.h"\n    export *\n}\n' >"$2/OctaPassVaultFFI/module.modulemap"
}
