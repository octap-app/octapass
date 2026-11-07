#!/usr/bin/env bash
# Builds the Safari apps: the extension's Safari build (apps/extension, `--target safari`), synced
# into Generated/, then xcodebuild for macOS and the iOS Simulator. Unsigned: macOS is signed ad hoc,
# the simulator build is signed to run locally. With macOS, it then runs scripts/check-extension.swift,
# which loads the extension into WebKit's extension runtime (macOS 15.4 or later).
#
#   apps/safari/scripts/build.sh [--skip-extension] [--platform macos|ios] [--configuration Debug|Release]
#
# DEVELOPMENT_TEAM=<team id> signs the macOS app with that team's "Apple Development" certificate
# (or CODE_SIGN_IDENTITY), so Safari lists the extension without "Allow unsigned extensions".
#
# Products land in apps/safari/build/DerivedData/Build/Products/<configuration>[-iphonesimulator]/.

set -euo pipefail

safari="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$safari/../.." && pwd)"
extension="$repo/apps/extension"
generated="$safari/Generated"
derived="$safari/build/DerivedData"

skip_extension=false
platforms=(macos ios)
configuration=Debug
while (($#)); do
  case "$1" in
    --skip-extension) skip_extension=true ;;
    --platform) platforms=("$2"); shift ;;
    --configuration) configuration="$2"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ $skip_extension == false ]]; then
  pnpm --dir "$repo" --filter @octapass/core build:if-stale
  pnpm --dir "$repo" --filter @octapass/extension exec node scripts/build.ts --target safari
fi

# The Xcode project lists the extension's top-level files one by one (each is copied to the root of
# the .appex), so a new one has to be added there too.
expected="app.html assets background.js content.js icons manifest.json page.js passkey.html"
actual="$(ls "$extension/dist/safari" | sort | xargs)"
if [[ "$actual" != "$expected" ]]; then
  echo "apps/extension/dist/safari has: $actual" >&2
  echo "OctaPass.xcodeproj expects:      $expected" >&2
  exit 1
fi
mkdir -p "$generated/Fonts"
rsync -a --delete "$extension/dist/safari/" "$generated/Extension/"
cp "$extension/node_modules/@fontsource-variable/mona-sans/files/mona-sans-latin-wdth-normal.woff2" "$generated/Fonts/MonaSans.woff2"

identity="${CODE_SIGN_IDENTITY:-}"
if [[ -z $identity ]]; then
  if [[ -n ${DEVELOPMENT_TEAM:-} ]]; then identity="Apple Development"; else identity="-"; fi
fi

build() {
  xcodebuild -project "$safari/OctaPass.xcodeproj" -configuration "$configuration" -derivedDataPath "$derived" -quiet "$@" build
}

for platform in "${platforms[@]}"; do
  case "$platform" in
    macos)
      build -scheme "Octa Pass (macOS)" -destination "generic/platform=macOS" \
        CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$identity" DEVELOPMENT_TEAM="${DEVELOPMENT_TEAM:-}"
      echo "Built $derived/Build/Products/$configuration/Octa Pass.app"
      if [[ "$(printf '%s\n' 15.4 "$(sw_vers -productVersion)" | sort -V | head -1)" == 15.4 ]]; then
        swiftc -target "$(uname -m)-apple-macos15.4" "$safari/scripts/check-extension.swift" -o "$safari/build/check-extension"
        "$safari/build/check-extension" "$generated/Extension"
      else
        echo "Skipped the WebKit check: it needs macOS 15.4 or later."
      fi
      ;;
    ios)
      build -scheme "Octa Pass (iOS)" -destination "generic/platform=iOS Simulator"
      echo "Built $derived/Build/Products/$configuration-iphonesimulator/Octa Pass.app"
      ;;
    *) echo "Unknown platform: $platform" >&2; exit 2 ;;
  esac
done
