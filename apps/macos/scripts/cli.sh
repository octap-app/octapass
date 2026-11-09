#!/usr/bin/env bash
# An Xcode build phase of OctaPassMac (project.yml): builds the `octapass` CLI and its helpers
# (git-credential-octapass, octapass-git-sign, docker-credential-octapass) for the architectures
# being built, puts them next to the app's executable in Contents/MacOS, and signs them with the
# app's identity, the hardened runtime and the app's App Group, so the CLI reaches the app's
# `cli.sock` in the group's container as a member of the group (plan 05, 2026-11-09). Settings →
# Command-line tool links `octapass` into /usr/local/bin. The CLI isn't sandboxed: it's started
# from a terminal and keeps its own data in ~/Library/Application Support/com.octapass.cli.
#
# Debug builds get debug programs, like octapass-native-host (scripts/native-host.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
: "${TARGET_BUILD_DIR:?run from Xcode}" "${EXECUTABLE_FOLDER_PATH:?run from Xcode}"
PROGRAMS=(octapass git-credential-octapass octapass-git-sign docker-credential-octapass)

profile=debug
flags=()
if [[ "${CONFIGURATION:-Debug}" != "Debug" ]]; then
  profile=release
  flags+=(--release)
fi

triples=()
for arch in ${ARCHS:-$(uname -m)}; do
  case "$arch" in
    arm64) triple=aarch64-apple-darwin ;;
    x86_64) triple=x86_64-apple-darwin ;;
    *) echo "error: no Rust target for $arch" >&2; exit 1 ;;
  esac
  # Xcode's environment (its compilers, SDK and flags) is for the app, not for cargo.
  env -i HOME="$HOME" PATH="$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}" \
    cargo build --quiet --locked --manifest-path "$ROOT/Cargo.toml" -p octapass-cli \
      --target "$triple" ${flags[@]+"${flags[@]}"}
  triples+=("$triple")
done

folder="$TARGET_BUILD_DIR/$EXECUTABLE_FOLDER_PATH"
mkdir -p "$folder"
for program in "${PROGRAMS[@]}"; do
  built=()
  for triple in "${triples[@]}"; do
    built+=("$ROOT/target/$triple/$profile/$program")
  done
  lipo -create "${built[@]}" -output "$folder/$program"
done

# No identity: a build with signing off (CODE_SIGNING_ALLOWED=NO).
if [[ -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]]; then
  echo "note: the CLI is not signed (signing is off)"
  exit 0
fi
group="${DEVELOPMENT_TEAM:?no signing team}.app.octap"
entitlements="$DERIVED_FILE_DIR/octapass-cli.entitlements"
mkdir -p "$DERIVED_FILE_DIR"
cat >"$entitlements" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${group}</string>
	</array>
</dict>
</plist>
PLIST
for program in "${PROGRAMS[@]}"; do
  codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --options runtime --timestamp=none \
    --identifier "${PRODUCT_BUNDLE_IDENTIFIER}.${program}" --entitlements "$entitlements" "$folder/$program"
done
