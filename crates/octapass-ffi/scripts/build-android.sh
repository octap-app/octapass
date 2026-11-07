#!/usr/bin/env bash
# Builds liboctapass_ffi.so for arm64-v8a and x86_64 (Android 9, API 28, and later) into
# apps/android/core/jniLibs and regenerates the Kotlin bindings next to it.
# Needs the Android NDK: $ANDROID_NDK_HOME, or the newest one under $ANDROID_HOME/ndk.
source "$(dirname "$0")/common.sh"

API=28
ndk="${ANDROID_NDK_HOME:-$(ls -d "${ANDROID_HOME:?set ANDROID_HOME or ANDROID_NDK_HOME}"/ndk/* | sort -V | tail -1)}"
toolchain="$(echo "$ndk"/toolchains/llvm/prebuilt/*/bin)"

for pair in aarch64-linux-android:arm64-v8a x86_64-linux-android:x86_64; do
  target="${pair%%:*}" abi="${pair##*:}"
  env_target="$(echo "$target" | tr '[:lower:]-' '[:upper:]_')"
  export "CARGO_TARGET_${env_target}_LINKER=$toolchain/$target$API-clang"
  export "CC_${target//-/_}=$toolchain/$target$API-clang"
  export "AR_${target//-/_}=$toolchain/llvm-ar"
  cargo build --manifest-path "$ROOT/Cargo.toml" -p octapass-ffi --release --target "$target"
  # Stripped here, not by cargo: bindgen reads the UniFFI metadata from the unstripped library.
  mkdir -p "$KOTLIN_PROJECT/jniLibs/$abi"
  "$toolchain/llvm-strip" --strip-unneeded "$TARGET/$target/release/liboctapass_ffi.so" \
    -o "$KOTLIN_PROJECT/jniLibs/$abi/liboctapass_ffi.so"
done

generate_kotlin "$TARGET/aarch64-linux-android/release/liboctapass_ffi.so" "$WORK/android/generated"
cp "$WORK/android/generated/app/octapass/core/octapass_ffi.kt" \
  "$KOTLIN_PROJECT/src/main/kotlin/app/octapass/core/octapass_ffi.kt"
echo "Built $KOTLIN_PROJECT/jniLibs"
