#!/usr/bin/env bash
# The native Mac app's release build (pnpm build:macos, plan 19):
#
#   build/Release/Octa Pass.app   the app
#   build/Octa Pass.dmg           a disk image with the app and a link to Applications
#
# Signed for development with APPLE_DEVELOPMENT_TEAM, else the team the iPhone builds use
# (apps/ios/Signing.local.xcconfig): the data-protection Keychain and the App Group need a signed
# app, so there's no unsigned build. A development-signed app opens on the Macs in the team's
# profile, this one included (Xcode registers it). Developer ID signing and notarization, for
# anyone's Mac, come with the switch from the Tauri app (plan 19, phase 4).
#
# OCTAPASS_BUILD_SERVER_URL is the server the app offers as "Octa Pass" (pnpm build:macos picks it,
# see scripts/build-app.sh); without it, project.yml's.
source "$(dirname "$0")/common.sh"

if (($#)); then
  echo "usage: apps/macos/scripts/build.sh" >&2
  exit 2
fi

team="${APPLE_DEVELOPMENT_TEAM:-}"
if [[ -z "$team" && -f "$ROOT/apps/ios/Signing.local.xcconfig" ]]; then
  team="$(sed -n 's/^DEVELOPMENT_TEAM = //p' "$ROOT/apps/ios/Signing.local.xcconfig")"
fi
if [[ -z "$team" ]]; then
  echo "The Mac app has to be signed: set APPLE_DEVELOPMENT_TEAM, or run pnpm dev:ios:device once to pick a team." >&2
  exit 1
fi
echo "Signing with team $team" >&2
settings=("DEVELOPMENT_TEAM=$team" -allowProvisioningUpdates)
if [[ -n "${OCTAPASS_BUILD_SERVER_URL:-}" ]]; then
  settings+=("OCTAPASS_SERVER_URL=$OCTAPASS_BUILD_SERVER_URL")
fi
if [[ -n "${OCTAPASS_BUILD_NUMBER:-}" ]]; then
  settings+=("CURRENT_PROJECT_VERSION=$OCTAPASS_BUILD_NUMBER")
fi

ensure_vault_framework
ensure_project
xcode release -project "$MAC/OctaPassMac.xcodeproj" -scheme OctaPassMac -configuration Release \
  -derivedDataPath "$DERIVED" -destination 'generic/platform=macOS' "${settings[@]}" build

out="$MAC/build/Release"
rm -rf "$out"
mkdir -p "$out"
ditto "$DERIVED/Build/Products/Release/Octa Pass.app" "$out/Octa Pass.app"
codesign --verify --strict "$out/Octa Pass.app"
echo "Built $out/Octa Pass.app"

# The disk image: the app next to a link to Applications, to drag it across.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
ditto "$out/Octa Pass.app" "$stage/Octa Pass.app"
ln -s /Applications "$stage/Applications"
dmg="$MAC/build/Octa Pass.dmg"
rm -f "$dmg"
hdiutil create -quiet -volname "Octa Pass" -srcfolder "$stage" -format UDZO "$dmg"
echo "Built $dmg"
