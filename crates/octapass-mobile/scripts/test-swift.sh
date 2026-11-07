#!/usr/bin/env bash
# Runs the Swift binding tests in apps/ios/Packages/OctaPassVault on this Mac, against a host
# build of the library and the real sync server in development mode (started here unless
# OCTAPASS_TEST_SERVER points at one). Fails when the committed bindings are out of date.
source "$(dirname "$0")/common.sh"

export MACOSX_DEPLOYMENT_TARGET=14.0
cargo build --manifest-path "$ROOT/Cargo.toml" -p octapass-mobile --release
library="$TARGET/release/liboctapass_mobile.a"

generate_swift "$library" "$WORK/swift-testing"
check_bindings "$SWIFT_SOURCE" "$WORK/swift-testing/OctaPassVault.swift"
HEADERS="$WORK/swift-testing-headers"
swift_headers "$WORK/swift-testing" "$HEADERS"
create_xcframework "$SWIFT_PACKAGE/.testing/OctaPassVaultFFI.xcframework" "$library"

start_dev_server
OCTAPASS_VAULT_TESTING=1 swift test --package-path "$SWIFT_PACKAGE" "$@"
