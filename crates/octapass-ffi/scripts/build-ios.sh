#!/usr/bin/env bash
# Builds OctaPassCoreFFI.xcframework into apps/ios/Packages/OctaPassCore and regenerates the Swift
# bindings next to it: iOS device arm64, the iOS simulator (arm64 + x86_64), and macOS (arm64 +
# x86_64) for the Mac app's AutoFill extension (plan 19).
source "$(dirname "$0")/common.sh"

export IPHONEOS_DEPLOYMENT_TARGET=17.0
export MACOSX_DEPLOYMENT_TARGET=14.0
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --manifest-path "$ROOT/Cargo.toml" -p octapass-ffi --release --target "$target"
done

ios="$WORK/ios"
rm -rf "$ios" && mkdir -p "$ios/simulator" "$ios/macos"
lipo -create \
  "$TARGET/aarch64-apple-ios-sim/release/liboctapass_ffi.a" \
  "$TARGET/x86_64-apple-ios/release/liboctapass_ffi.a" \
  -output "$ios/simulator/liboctapass_ffi.a"
lipo -create \
  "$TARGET/aarch64-apple-darwin/release/liboctapass_ffi.a" \
  "$TARGET/x86_64-apple-darwin/release/liboctapass_ffi.a" \
  -output "$ios/macos/liboctapass_ffi.a"

generate_swift "$TARGET/aarch64-apple-ios/release/liboctapass_ffi.a" "$ios/generated"
HEADERS="$ios/headers"
mkdir -p "$HEADERS"
cp "$ios/generated/OctaPassCoreFFI.h" "$ios/generated/module.modulemap" "$HEADERS/"
cp "$ios/generated/OctaPassCore.swift" "$SWIFT_PACKAGE/Sources/OctaPassCore/OctaPassCore.swift"

create_xcframework "$SWIFT_PACKAGE/OctaPassCoreFFI.xcframework" \
  "$TARGET/aarch64-apple-ios/release/liboctapass_ffi.a" \
  "$ios/simulator/liboctapass_ffi.a" \
  "$ios/macos/liboctapass_ffi.a"
echo "Built $SWIFT_PACKAGE/OctaPassCoreFFI.xcframework"
