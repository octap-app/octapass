#!/usr/bin/env bash
# Builds the native Mac app (plan 19) and opens it. Debug build, signed with the team in
# apps/ios/Signing.local.xcconfig (the Keychain and the App Group need a signed build; Xcode makes
# the development profile with -allowProvisioningUpdates).
#
#   OCTAPASS_SERVER_URL=http://127.0.0.1:8080 apps/macos/scripts/run.sh   # a development server
#   apps/macos/scripts/run.sh --build-only
source "$(dirname "$0")/common.sh"

ensure_vault_framework
ensure_project
xcode build -project "$MAC/OctaPassMac.xcodeproj" -scheme OctaPassMac -configuration Debug \
  -derivedDataPath "$DERIVED" -destination 'platform=macOS' -allowProvisioningUpdates build
app="$DERIVED/Build/Products/Debug/Octa Pass.app"
echo "Built $app"
[[ "${1:-}" == "--build-only" ]] && exit 0

# Through `open`, not the binary directly: started from a shell, macOS 26 lists the app's menu bar
# icon under the terminal's app (System Settings → Menu Bar), and keeps it there for later launches
# too. `--env` still hands OCTAPASS_SERVER_URL (when set) to the app; logs go to this terminal.
env=()
[[ -z "${OCTAPASS_SERVER_URL:-}" ]] || env=(--env "OCTAPASS_SERVER_URL=$OCTAPASS_SERVER_URL")
open -n ${env[@]+"${env[@]}"} --stdout "$(tty 2>/dev/null || echo /dev/null)" --stderr "$(tty 2>/dev/null || echo /dev/null)" "$app"
