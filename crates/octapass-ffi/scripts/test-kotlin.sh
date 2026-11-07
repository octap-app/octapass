#!/usr/bin/env bash
# Runs the Kotlin tests in apps/android/core on the JVM, against a host build of the
# library with the in-process TestServer (feature `test-server`, never in the app builds).
source "$(dirname "$0")/common.sh"

cargo build --manifest-path "$ROOT/Cargo.toml" -p octapass-ffi --release --features test-server
case "$(uname)" in
  Darwin) library="$TARGET/release/liboctapass_ffi.dylib" ;;
  *) library="$TARGET/release/liboctapass_ffi.so" ;;
esac

testing="$WORK/kotlin-testing"
generate_kotlin "$library" "$testing/kotlin"
mkdir -p "$testing/lib"
cp "$library" "$testing/lib/"

cd "$KOTLIN_PROJECT"
./gradlew test --console=plain -PoctapassFfiTesting="$testing" "$@"
