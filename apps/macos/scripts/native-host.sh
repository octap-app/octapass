#!/usr/bin/env bash
# An Xcode build phase of OctaPassMac (project.yml): builds octapass-native-host, the browser
# extension's native messaging host (apps/desktop/crates/native-host), for the architectures
# being built, puts it next to the app's executable in Contents/MacOS, and signs it with the
# app's identity and the hardened runtime. The app's browser bridge answers only that binary,
# signed by the app's own team (plan 19, phase 3).
#
# Debug builds get a debug host, which also accepts the development build of the extension, as the
# app does in a debug build (DesktopServices.development). Cargo runs offline: the vault library's
# build already fetched every crate the host uses.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${TARGET_BUILD_DIR:?run from Xcode}" "${EXECUTABLE_FOLDER_PATH:?run from Xcode}"

profile=debug
flags=()
if [[ "${CONFIGURATION:-Debug}" != "Debug" ]]; then
  profile=release
  flags+=(--release)
fi

libraries=()
for arch in ${ARCHS:-$(uname -m)}; do
  case "$arch" in
    arm64) triple=aarch64-apple-darwin ;;
    x86_64) triple=x86_64-apple-darwin ;;
    *) echo "error: no Rust target for $arch" >&2; exit 1 ;;
  esac
  # Xcode's environment (its compilers, SDK and flags) is for the app, not for cargo.
  env -i HOME="$HOME" PATH="$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}" \
    ${OCTAPASS_EXTRA_EXTENSION_IDS:+OCTAPASS_EXTRA_EXTENSION_IDS="$OCTAPASS_EXTRA_EXTENSION_IDS"} \
    cargo build --quiet --offline --manifest-path "$ROOT/Cargo.toml" -p octapass-native-host \
      --bin octapass-native-host --target "$triple" ${flags[@]+"${flags[@]}"}
  libraries+=("$ROOT/target/$triple/$profile/octapass-native-host")
done

host="$TARGET_BUILD_DIR/$EXECUTABLE_FOLDER_PATH/octapass-native-host"
mkdir -p "$(dirname "$host")"
lipo -create "${libraries[@]}" -output "$host"

# No identity: a build with signing off (CODE_SIGNING_ALLOWED=NO), which can't run the bridge.
if [[ -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]]; then
  echo "note: octapass-native-host is not signed (signing is off)"
  exit 0
fi
# Sandboxed, which the Mac App Store requires of every executable in the app (the browsers start
# this one, so it can't inherit the app's sandbox), and in the App Group, so it reaches the app's
# container (its socket) as a member of the group: OCTAPASS_APP_GROUP in project.yml, `<team>.app.octap`.
group="${DEVELOPMENT_TEAM:?no signing team}.app.octap"
entitlements="$DERIVED_FILE_DIR/octapass-native-host.entitlements"
mkdir -p "$DERIVED_FILE_DIR"
cat >"$entitlements" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.app-sandbox</key>
	<true/>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${group}</string>
	</array>
</dict>
</plist>
EOF
codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --options runtime --timestamp=none \
  --identifier "${PRODUCT_BUNDLE_IDENTIFIER}.native-host" --entitlements "$entitlements" "$host"
