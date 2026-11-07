#!/usr/bin/env bash
# Runs the Swift tests of the iOS packages on this Mac: OctaPassKeychain, OctaPassWifi,
# OctaPassWatchCodes, and
# OctaPassAutoFillKit against the core's test flavour (in-process TestServer), which
# crates/octapass-ffi/scripts/test-swift.sh builds (it runs the bindings' own tests too).
set -euo pipefail
packages="$(cd "$(dirname "$0")/../Packages" && pwd)"
root="$(cd "$packages/../../.." && pwd)"

"$root/crates/octapass-ffi/scripts/test-swift.sh"
swift test --package-path "$packages/Keychain"
swift test --package-path "$packages/Wifi"
swift test --package-path "$packages/WatchCodes"
OCTAPASS_FFI_TESTING=1 swift test --package-path "$packages/AutoFillKit"
