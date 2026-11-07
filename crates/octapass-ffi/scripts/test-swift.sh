#!/usr/bin/env bash
# Runs the Swift tests in apps/ios/Packages/OctaPassCore on this Mac, against a host build of the
# library with the in-process TestServer (feature `test-server`, never in the app builds).
source "$(dirname "$0")/common.sh"

export MACOSX_DEPLOYMENT_TARGET=14.0
cargo build --manifest-path "$ROOT/Cargo.toml" -p octapass-ffi --release --features test-server
library="$TARGET/release/liboctapass_ffi.a"

testing="$SWIFT_PACKAGE/.testing"
generate_swift "$library" "$WORK/swift-testing"
mkdir -p "$testing/Sources/OctaPassCore"
cp "$WORK/swift-testing/OctaPassCore.swift" "$testing/Sources/OctaPassCore/"
HEADERS="$WORK/swift-testing/headers"
mkdir -p "$HEADERS"
cp "$WORK/swift-testing/OctaPassCoreFFI.h" "$WORK/swift-testing/module.modulemap" "$HEADERS/"
create_xcframework "$testing/OctaPassCoreFFI.xcframework" "$library"

OCTAPASS_FFI_TESTING=1 swift test --package-path "$SWIFT_PACKAGE" "$@"
