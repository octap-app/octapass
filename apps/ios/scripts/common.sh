# Shared by the scripts in this folder. Source it, don't run it.
set -euo pipefail

IOS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$IOS/../.." && pwd)"
DERIVED="$IOS/build/DerivedData"
# The Simulator the tests run on when DEVICE doesn't name one. DEVICE isn't set here: device.sh
# reads it as the phone to install on.
DEFAULT_SIMULATOR="iPhone 17 Pro"
# shellcheck source=../../../scripts/lib/prompt.sh
source "$ROOT/scripts/lib/prompt.sh"
# shellcheck source=../../../scripts/lib/stale.sh
source "$ROOT/scripts/lib/stale.sh"

# The XCFrameworks the app (crates/octapass-mobile) and the AutoFill extension (crates/octapass-ffi)
# link. They're build outputs, rebuilt when their Rust sources change: the committed Swift bindings
# change with the Rust API, and a framework from older sources fails to compile against them.
ensure_vault_framework() {
  rebuild_if_stale octapass-mobile "$IOS/Packages/OctaPassVault/OctaPassVaultFFI.xcframework" \
    "$ROOT/crates/octapass-mobile/scripts/build-ios.sh" "$ROOT/crates/octapass-mobile/scripts/common.sh"
  rebuild_if_stale octapass-ffi "$IOS/Packages/OctaPassCore/OctaPassCoreFFI.xcframework" \
    "$ROOT/crates/octapass-ffi/scripts/build-ios.sh" "$ROOT/crates/octapass-ffi/scripts/common.sh"
}

# xcode NAME ARGUMENTS…: runs xcodebuild ARGUMENTS with its output in build/NAME.log. Prints the
# result line when it works; when it fails, the error lines and the log's path, since the last
# lines of the output rarely say what went wrong.
xcode() {
  local log="$IOS/build/$1.log"
  shift
  mkdir -p "$IOS/build"
  if xcodebuild "$@" >"$log" 2>&1; then
    grep -E '^\*\* .* SUCCEEDED \*\*' "$log" | tail -1 || true
    return 0
  fi
  echo "xcodebuild failed:" >&2
  grep -E '(^|[^A-Za-z])error: ' "$log" | awk '!seen[$0]++' | head -30 >&2 || true
  echo "The full log: $log" >&2
  return 1
}

# Regenerates the Xcode project when project.yml is newer.
ensure_project() {
  if [[ ! -d "$IOS/OctaPass.xcodeproj" || "$IOS/project.yml" -nt "$IOS/OctaPass.xcodeproj/project.pbxproj" ]]; then
    (cd "$IOS" && xcodegen generate --quiet)
  fi
}

# Starts the real sync server in development mode (email codes on screen, no rate limits) on a
# free port with an empty database, and sets OCTAPASS_TEST_SERVER. Set OCTAPASS_TEST_SERVER first
# to use a running one. The server stops when the script exits; only its PID is killed.
start_dev_server() {
  if [[ -n "${OCTAPASS_TEST_SERVER:-}" ]]; then
    return
  fi
  CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p octapass-server
  local port data
  port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  data="$(mktemp -d -t octapass-ios)"
  OCTAPASS_BIND="127.0.0.1:$port" OCTAPASS_DEV_MODE=true OCTAPASS_RATE_LIMITS=off \
    OCTAPASS_DATA_DIR="$data" "$ROOT/target/debug/octapass-server" >"$data/server.log" 2>&1 &
  SERVER_PID=$!
  cleanup+=("kill $SERVER_PID 2>/dev/null; rm -rf '$data'")
  export OCTAPASS_TEST_SERVER="http://localhost:$port"
  for _ in $(seq 1 100); do
    if curl -sf "$OCTAPASS_TEST_SERVER/v1/server-info" >/dev/null; then
      return
    fi
    sleep 0.2
  done
  cat "$data/server.log" >&2
  echo "the development server didn't start" >&2
  exit 1
}

# Boots the Simulator, enrols a face, and answers every Face ID prompt with a match while the
# script runs (the Tauri app's tests did the same).
prepare_simulator() {
  xcrun simctl boot "$DEVICE" 2>/dev/null || true
  xcrun simctl bootstatus "$DEVICE" -b >/dev/null
  xcrun simctl spawn "$DEVICE" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
  xcrun simctl spawn "$DEVICE" notifyutil -p com.apple.BiometricKit.enrollmentChanged
  ( while true; do xcrun simctl spawn "$DEVICE" notifyutil -p com.apple.BiometricKit_Sim.pearl.match >/dev/null 2>&1; sleep 2; done ) &
  MATCHER_PID=$!
  cleanup+=("kill $MATCHER_PID 2>/dev/null")
}

# Steps to run when the script exits. The list can be empty, and macOS's bash 3.2 treats
# "${cleanup[@]}" on an empty list as an unset variable, hence the ${cleanup[@]+…} guard.
cleanup=()
run_cleanup() {
  local step
  for step in ${cleanup[@]+"${cleanup[@]}"}; do eval "$step" || true; done
}
trap run_cleanup EXIT
