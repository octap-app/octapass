#!/usr/bin/env bash
# Shared by the Mac app's run.sh and build.sh. Sourced, not run.
set -euo pipefail
MAC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$MAC/../.." && pwd)"
DERIVED="$MAC/build/DerivedData"
# shellcheck source=../../../scripts/lib/stale.sh
source "$ROOT/scripts/lib/stale.sh"

# The vault library and the AutoFill extension's core (octapass-ffi) with their macOS slices,
# rebuilt when the Rust sources changed.
ensure_vault_framework() {
  rebuild_if_stale octapass-mobile "$ROOT/apps/ios/Packages/OctaPassVault/OctaPassVaultFFI.xcframework" \
    "$ROOT/crates/octapass-mobile/scripts/build-ios.sh" "$ROOT/crates/octapass-mobile/scripts/common.sh"
  rebuild_if_stale octapass-ffi "$ROOT/apps/ios/Packages/OctaPassCore/OctaPassCoreFFI.xcframework" \
    "$ROOT/crates/octapass-ffi/scripts/build-ios.sh" "$ROOT/crates/octapass-ffi/scripts/common.sh"
}

# The Xcode project, generated again when project.yml changed.
ensure_project() {
  if ! command -v xcodegen >/dev/null; then
    echo "The Mac app needs XcodeGen: brew install xcodegen" >&2
    exit 1
  fi
  if [[ ! -d "$MAC/OctaPassMac.xcodeproj" || "$MAC/project.yml" -nt "$MAC/OctaPassMac.xcodeproj/project.pbxproj" ]]; then
    (cd "$MAC" && xcodegen generate --quiet)
  fi
}

# xcode LOGNAME ARGS…: xcodebuild with its output in build/LOGNAME.log; on failure, the errors.
xcode() {
  local log="$MAC/build/$1.log"
  shift
  mkdir -p "$MAC/build"
  if ! xcodebuild "$@" >"$log" 2>&1; then
    echo "xcodebuild failed:" >&2
    grep -E '(^|[^A-Za-z])error: ' "$log" | awk '!seen[$0]++' | head -40 >&2 || true
    echo "The full log: $log" >&2
    exit 1
  fi
}
