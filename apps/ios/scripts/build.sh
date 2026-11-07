#!/usr/bin/env bash
# The App Store build of the app and its AutoFill extension (pnpm build:ios):
#
#   pnpm build:ios            build/OctaPass.xcarchive, and build/AppStore/Octa Pass.ipa to upload
#                             with Transporter or `xcrun altool --upload-app`
#   pnpm build:ios --upload   the same archive, uploaded to App Store Connect straight away
#
# Signed with APPLE_DEVELOPMENT_TEAM, else the team in device.env, else the one pnpm dev:ios:device
# last used; without a team it's an unsigned archive only.
#
# The archive is signed for development, like every build on this Mac. App Store Connect takes only
# distribution signing (error 90161, "A distribution provisioning profile should be used"), so the
# export signs it again for App Store Connect: Xcode makes the Apple Distribution certificate and the
# App Store profiles of the app and the extension itself (automatic signing). That needs the team's
# Apple account in Xcode → Settings → Accounts, with the Admin or App Manager role, and the app in
# App Store Connect with the bundle ID app.octap.ios. Xcode also raises the build number past the
# ones already uploaded. OCTAPASS_BUILD_NUMBER sets it instead.
#
# OCTAPASS_BUILD_SERVER_URL is the server the app offers as "Octa Pass" (pnpm build:ios picks it,
# see scripts/build-app.sh); without it, project.yml's.
source "$(dirname "$0")/common.sh"
load_env "$IOS/device.env"

destination=export
while (($#)); do
  case "$1" in
    --upload) destination=upload ;;
    *) echo "usage: apps/ios/scripts/build.sh [--upload]" >&2; exit 2 ;;
  esac
  shift
done

team="${APPLE_DEVELOPMENT_TEAM:-}"
if [[ -z "$team" && -f "$IOS/Signing.local.xcconfig" ]]; then
  team="$(sed -n 's/^DEVELOPMENT_TEAM = //p' "$IOS/Signing.local.xcconfig")"
fi
settings=(CODE_SIGNING_ALLOWED=NO)
if [[ -n "$team" ]]; then
  printf 'DEVELOPMENT_TEAM = %s\n' "$team" >"$IOS/Signing.local.xcconfig"
  settings=(-allowProvisioningUpdates)
  echo "Signing with team $team" >&2
elif [[ "$destination" == upload ]]; then
  echo "--upload needs a team: set APPLE_DEVELOPMENT_TEAM, or run pnpm dev:ios:device once." >&2
  exit 1
else
  echo "Unsigned: no team in APPLE_DEVELOPMENT_TEAM or device.env, and pnpm dev:ios:device hasn't picked one." >&2
fi
if [[ -n "${OCTAPASS_BUILD_SERVER_URL:-}" ]]; then
  settings+=("OCTAPASS_SERVER_URL=$OCTAPASS_BUILD_SERVER_URL")
fi
if [[ -n "${OCTAPASS_BUILD_NUMBER:-}" ]]; then
  settings+=("CURRENT_PROJECT_VERSION=$OCTAPASS_BUILD_NUMBER")
fi

ensure_vault_framework
ensure_project
archive="$IOS/build/OctaPass.xcarchive"
xcode archive archive -project "$IOS/OctaPass.xcodeproj" -scheme OctaPass -configuration Release \
  -destination "generic/platform=iOS" -derivedDataPath "$DERIVED" \
  -archivePath "$archive" "${settings[@]}"
echo "Built $archive"
[[ -n "$team" ]] || exit 0

# The export's options; method app-store-connect needs Xcode 15.3 or later.
options="$IOS/build/AppStoreExportOptions.plist"
manage=true
[[ -z "${OCTAPASS_BUILD_NUMBER:-}" ]] || manage=false
cat >"$options" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>app-store-connect</string>
	<key>destination</key>
	<string>$destination</string>
	<key>signingStyle</key>
	<string>automatic</string>
	<key>teamID</key>
	<string>$team</string>
	<key>manageAppVersionAndBuildNumber</key>
	<$manage/>
	<key>uploadSymbols</key>
	<true/>
</dict>
</plist>
PLIST
exported="$IOS/build/AppStore"
rm -rf "$exported"
xcode export -exportArchive -archivePath "$archive" -exportPath "$exported" \
  -exportOptionsPlist "$options" -allowProvisioningUpdates
if [[ "$destination" == upload ]]; then
  echo "Uploaded to App Store Connect; it shows under TestFlight once Apple has processed it."
else
  echo "Built $exported/Octa Pass.ipa, signed for App Store Connect. Upload it with Transporter, or run pnpm build:ios --upload."
fi
