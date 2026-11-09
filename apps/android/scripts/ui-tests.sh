#!/usr/bin/env bash
# Runs the app's Compose UI tests (app/src/androidTest) on an emulator against a fresh development
# server, and saves the screenshots the tests take (ScreenshotsTest, and any failing test's, under
# failures/) to the folder given as $1 (default build/screenshots). More arguments go to Gradle:
#   apps/android/scripts/ui-tests.sh
#   apps/android/scripts/ui-tests.sh build/shots -Pandroid.testInstrumentationRunnerArguments.class=app.octap.android.ScreenshotsTest
#   ANDROID_SERIAL=emulator-5584 apps/android/scripts/ui-tests.sh
#   OCTAPASS_TEST_SERVER=http://localhost:8193 apps/android/scripts/ui-tests.sh   (a running server)
#
# The emulator needs a screen lock for the device-unlock tests: this sets the PIN 1111 when it has
# none. ANDROID_SERIAL picks the emulator when several run. Needs Java 17, ANDROID_HOME with the SDK
# and NDK, and the Rust Android targets (the library is rebuilt when its Rust sources changed).
set -euo pipefail

android="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$android/../.." && pwd)"
# shellcheck source=../../../scripts/lib/stale.sh
source "$root/scripts/lib/stale.sh"
adb() { "${ANDROID_HOME:?set ANDROID_HOME}/platform-tools/adb" "$@"; }

cleanup=()
run_cleanup() {
  local step
  for step in ${cleanup[@]+"${cleanup[@]}"}; do eval "$step" || true; done
}
trap run_cleanup EXIT

shots="$(mkdir -p "${1:-$android/build/screenshots}" && cd "${1:-$android/build/screenshots}" && pwd)"

if [[ -z "${ANDROID_SERIAL:-}" ]]; then
  serials="$(adb devices | awk 'NR > 1 && $2 == "device" { print $1 }')"
  if [[ "$(printf '%s\n' "$serials" | grep -c .)" -ne 1 ]]; then
    echo "Start one emulator, or set ANDROID_SERIAL to one of: $(echo $serials)" >&2
    exit 1
  fi
  ANDROID_SERIAL="$serials"
fi
# adb and Gradle's connected tasks both read it.
export ANDROID_SERIAL
adb wait-for-device
until [[ "$(adb shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]; do sleep 2; done

rebuild_if_stale octapass-mobile "$android/vault/jniLibs/x86_64/liboctapass_mobile.so" \
  "$root/crates/octapass-mobile/scripts/build-android.sh" "$root/crates/octapass-mobile/scripts/common.sh"

# The real sync server in development mode (email codes on screen, no rate limits) on a free port
# with an empty database. OCTAPASS_TEST_SERVER uses a running one instead.
if [[ -z "${OCTAPASS_TEST_SERVER:-}" ]]; then
  CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" cargo build --quiet --manifest-path "$root/Cargo.toml" -p octapass-server
  port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  data="$(mktemp -d -t octapass-android)"
  OCTAPASS_BIND="127.0.0.1:$port" OCTAPASS_DEV_MODE=true OCTAPASS_RATE_LIMITS=off \
    OCTAPASS_DATA_DIR="$data" "$root/target/debug/octapass-server" >"$data/server.log" 2>&1 &
  cleanup+=("kill $! 2>/dev/null; rm -rf '$data'")
  OCTAPASS_TEST_SERVER="http://localhost:$port"
  for _ in $(seq 1 100); do
    curl -sf "$OCTAPASS_TEST_SERVER/v1/server-info" >/dev/null && break
    sleep 0.2
  done
  curl -sf "$OCTAPASS_TEST_SERVER/v1/server-info" >/dev/null || { cat "$data/server.log" >&2; exit 1; }
fi
# The emulator reaches it as localhost through adb; the core allows plain http only for loopback.
port="${OCTAPASS_TEST_SERVER##*:}"
port="${port%%/*}"
adb reverse "tcp:$port" "tcp:$port" >/dev/null
cleanup+=("adb reverse --remove tcp:$port >/dev/null 2>&1")

# The device-unlock tests type this PIN into the system's prompt.
adb shell locksettings set-pin 1111 >/dev/null 2>&1 || true
# An emulator that started with the PIN set keeps the user's storage locked until it's typed once
# (the app can't start before that), so unlock the screen.
if adb shell dumpsys window | grep -A1 KeyguardServiceDelegate | grep -q 'showing=true'; then
  adb shell input keyevent KEYCODE_WAKEUP
  adb shell wm dismiss-keyguard
  sleep 2
  adb shell input text 1111
  adb shell input keyevent KEYCODE_ENTER
fi
for _ in $(seq 1 30); do adb shell ls /sdcard/ >/dev/null 2>&1 && break; sleep 2; done
# Keep the screen on while the tests run, whatever the emulator's screen timeout: once it sleeps,
# the screen lock comes back and covers the app.
adb shell svc power stayon true
cleanup+=("adb shell svc power stayon false >/dev/null 2>&1")
adb shell rm -rf /sdcard/octapass-screenshots

status=0
# The test app (services/uitests) is the other app OtherAppsTest fills; the tests switch to its
# plain keyboard, so put the usual one back afterwards.
cleanup+=("adb shell ime reset >/dev/null 2>&1")
(cd "$android" && ./gradlew :octapass-uitests:installDebug :app:connectedDebugAndroidTest "-PoctapassServer=$OCTAPASS_TEST_SERVER" "${@:2}") || status=$?

adb pull /sdcard/octapass-screenshots/. "$shots" >/dev/null 2>&1 || true
echo "Screenshots: $shots"
echo "Test report: $android/app/build/reports/androidTests/connected/debug/index.html"
exit "$status"
