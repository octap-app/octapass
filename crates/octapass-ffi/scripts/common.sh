# Shared by the build and test scripts in this directory. Source it, don't run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SWIFT_PACKAGE="$ROOT/apps/ios/Packages/OctaPassCore"
KOTLIN_PROJECT="$ROOT/apps/android/core"
TARGET="$ROOT/target"
WORK="$TARGET/octapass-ffi"

# uniffi-bindgen gets its own target directory, so building it doesn't change the features the
# library is built with.
bindgen() {
  cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p octapass-ffi --features bindgen \
    --target-dir "$TARGET/uniffi-bindgen" --bin "$@"
}

# Swift source, C header and module map for the library $1, into directory $2.
generate_swift() {
  rm -rf "$2"
  bindgen uniffi-bindgen-swift -- "$1" "$2" --swift-sources --headers --modulemap \
    --module-name OctaPassCoreFFI --modulemap-filename module.modulemap
}

# Kotlin source for the library $1, into directory $2 (package app.octap.core).
generate_kotlin() {
  rm -rf "$2"
  bindgen uniffi-bindgen -- generate --library "$1" --language kotlin --no-format --out-dir "$2"
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
