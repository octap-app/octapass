#!/usr/bin/env bash
# The Mac app's UI tests (plan 19) against the sync server in development mode, started here on a
# free port unless OCTAPASS_TEST_SERVER names one. Screenshots go to build/screenshots.
# UI automation needs developer mode (`sudo DevToolsSecurity -enable`, once), or macOS asks for
# your password on every run. The screenshots come out of the result bundle: the test runner is
# sandboxed and can't write them anywhere else.
set -euo pipefail
MAC="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$MAC/../.." && pwd)"
# shellcheck source=../../../crates/octapass-mobile/scripts/common.sh
source "$ROOT/crates/octapass-mobile/scripts/common.sh"

"$MAC/scripts/run.sh" --build-only
start_dev_server
mkdir -p "$MAC/build"
log="$MAC/build/ui-tests.log"
result="$MAC/build/ui-tests.xcresult"
rm -rf "$result" "$MAC/build/screenshots"
# Keeps the test's own screenshots (`snap`: "02-recovery-kit_0_<uuid>.png"), by their names; a
# failure also attaches XCTest's own records, which are dropped.
screenshots() {
  local out="$MAC/build/screenshots"
  mkdir -p "$out"
  xcrun xcresulttool export attachments --path "$result" --output-path "$out" >/dev/null 2>&1 || return 0
  python3 - "$out" <<'PY'
import json, os, re, sys
out = sys.argv[1]
for test in json.load(open(os.path.join(out, "manifest.json"))):
    for a in test["attachments"]:
        source = os.path.join(out, a["exportedFileName"])
        # Listed but not exported (a failure's own records, sometimes).
        if not os.path.exists(source):
            continue
        name = a.get("suggestedHumanReadableName", "").split("_0_")[0]
        if re.fullmatch(r"\d\d-[a-z0-9-]+", name):
            os.replace(source, os.path.join(out, name + ".png"))
        else:
            os.remove(source)
os.remove(os.path.join(out, "manifest.json"))
PY
}
if TEST_RUNNER_OCTAPASS_TEST_SERVER="$OCTAPASS_TEST_SERVER" \
  xcodebuild -project "$MAC/OctaPassMac.xcodeproj" -scheme OctaPassMac -configuration Debug \
  -derivedDataPath "$MAC/build/DerivedData" -destination 'platform=macOS' -allowProvisioningUpdates -resultBundlePath "$result" test "$@" >"$log" 2>&1; then
  screenshots
  grep -E '^\*\* TEST SUCCEEDED|Executed' "$log" | tail -2
else
  screenshots
  echo "The UI tests failed:" >&2
  grep -E 'error: |failed|XCTAssert' "$log" | awk '!seen[$0]++' | head -30 >&2 || true
  echo "The full log: $log" >&2
  exit 1
fi
