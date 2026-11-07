#!/usr/bin/env bash
# Builds OctaPassVaultFFI.xcframework into apps/ios/Packages/OctaPassVault and regenerates the
# Swift bindings next to it. One framework for every Apple app on the vault API: iOS device arm64,
# the iOS simulator (arm64 + x86_64), and macOS (arm64 + x86_64) for the Mac app (plan 19).
source "$(dirname "$0")/common.sh"

export IPHONEOS_DEPLOYMENT_TARGET=17.0
export MACOSX_DEPLOYMENT_TARGET=14.0
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --manifest-path "$ROOT/Cargo.toml" -p octapass-mobile --release --target "$target"
done

ios="$WORK/ios"
rm -rf "$ios" && mkdir -p "$ios/simulator" "$ios/macos"
lipo -create \
  "$TARGET/aarch64-apple-ios-sim/release/liboctapass_mobile.a" \
  "$TARGET/x86_64-apple-ios/release/liboctapass_mobile.a" \
  -output "$ios/simulator/liboctapass_mobile.a"
lipo -create \
  "$TARGET/aarch64-apple-darwin/release/liboctapass_mobile.a" \
  "$TARGET/x86_64-apple-darwin/release/liboctapass_mobile.a" \
  -output "$ios/macos/liboctapass_mobile.a"

generate_swift "$TARGET/aarch64-apple-ios/release/liboctapass_mobile.a" "$ios/generated"
HEADERS="$ios/headers"
swift_headers "$ios/generated" "$HEADERS"
cp "$ios/generated/OctaPassVault.swift" "$SWIFT_SOURCE"

create_xcframework "$SWIFT_PACKAGE/OctaPassVaultFFI.xcframework" \
  "$TARGET/aarch64-apple-ios/release/liboctapass_mobile.a" \
  "$ios/simulator/liboctapass_mobile.a" \
  "$ios/macos/liboctapass_mobile.a"
echo "Built $SWIFT_PACKAGE/OctaPassVaultFFI.xcframework"
