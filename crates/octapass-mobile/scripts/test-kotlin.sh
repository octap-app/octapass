#!/usr/bin/env bash
# Runs the Kotlin binding tests in apps/android/vault on the JVM, against a host build of the
# library and the real sync server in development mode (started here unless
# OCTAPASS_TEST_SERVER points at one). Fails when the committed bindings are out of date.
source "$(dirname "$0")/common.sh"

cargo build --manifest-path "$ROOT/Cargo.toml" -p octapass-mobile --release
case "$(uname)" in
  Darwin) library="$TARGET/release/liboctapass_mobile.dylib" ;;
  *) library="$TARGET/release/liboctapass_mobile.so" ;;
esac

generate_kotlin "$library" "$WORK/kotlin-testing"
check_bindings "$KOTLIN_SOURCE" "$WORK/kotlin-testing/app/octapass/vault/octapass_mobile.kt"
mkdir -p "$WORK/kotlin-lib"
cp "$library" "$WORK/kotlin-lib/"

start_dev_server
cd "$KOTLIN_PROJECT"
./gradlew test --console=plain -PoctapassVaultLibrary="$WORK/kotlin-lib" "$@"
