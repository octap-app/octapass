#!/usr/bin/env bash
# Runs the unit and UI tests on the iOS Simulator against a fresh development server, and saves
# the UI tests' screenshots to the folder given as $1 (default build/screenshots). More arguments
# go to xcodebuild, like -only-testing:OctaPassUITests/OnboardingTests.
#   DEVICE="iPad Pro 13-inch (M5)" scripts/ui-tests.sh
#   OCTAPASS_TEST_LANGUAGE=ar scripts/ui-tests.sh build/screenshots-ar
#   APPEARANCE=dark scripts/ui-tests.sh build/screenshots-dark
source "$(dirname "$0")/common.sh"
DEVICE="${DEVICE:-$DEFAULT_SIMULATOR}"

shots="$(mkdir -p "${1:-$IOS/build/screenshots}" && cd "${1:-$IOS/build/screenshots}" && pwd)"
ensure_vault_framework
ensure_project
start_dev_server
prepare_simulator
# Dark mode for the whole Simulator while the tests run (the app follows the system by default).
if [[ -n "${APPEARANCE:-}" ]]; then
  xcrun simctl ui "$DEVICE" appearance "$APPEARANCE"
  cleanup+=("xcrun simctl ui '$DEVICE' appearance light")
fi
# The sign-in page the AutoFill test opens in Safari, on a free port.
page_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
python3 -m http.server "$page_port" --bind 127.0.0.1 --directory "$IOS/OctaPassUITests/Fixtures" >/dev/null 2>&1 &
cleanup+=("kill $! 2>/dev/null")

TEST_RUNNER_SCREENSHOTS_DIR="$shots" \
TEST_RUNNER_OCTAPASS_TEST_SERVER="$OCTAPASS_TEST_SERVER" \
TEST_RUNNER_OCTAPASS_TEST_LANGUAGE="${OCTAPASS_TEST_LANGUAGE:-}" \
TEST_RUNNER_OCTAPASS_TEST_PAGE="http://localhost:$page_port" \
  xcodebuild test -project "$IOS/OctaPass.xcodeproj" -scheme OctaPass \
  -destination "platform=iOS Simulator,name=$DEVICE" -derivedDataPath "$DERIVED" \
  "${@:2}"
echo "Screenshots: $shots"
