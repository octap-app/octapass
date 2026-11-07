#!/usr/bin/env bash
# Builds one app for distribution. Run it through pnpm from the repository root:
#
#   pnpm build:extension   Chrome and Firefox, unpacked in apps/extension/dist/chrome and dist/firefox
#   pnpm build:safari      the Safari apps for macOS and the iOS Simulator (on a Mac)
#   pnpm build:ios         the iPhone and iPad app, signed for App Store Connect (on a Mac; --upload uploads it)
#   pnpm build:android     the Android app, as an unsigned release APK
#   pnpm build:desktop     the desktop app for the system you're on: build:macos on a Mac,
#                          build:windows on Windows, build:linux on Linux
#   pnpm build:macos       the Mac app (apps/macos, SwiftUI) and its disk image (on a Mac; plan 19)
#   pnpm build:windows     the Tauri app's Windows installer (on Windows, or cross-compiled on a Mac)
#   pnpm build:linux       the Tauri app's .deb, .rpm and AppImage packages (on Linux)
#   pnpm build:cli         the octapass command and its Git and Docker helpers
#   pnpm build:vscode      the VS Code extension, as a .vsix
#   pnpm build:jetbrains   the JetBrains plugin, as a .zip
#
# pnpm build:web, build:api and build (the website) are separate.
#
# The apps that sign in (the extensions, iOS, Android and the desktop app) offer one server as
# "Octa Pass" on their sign-in screen, and anyone can still type another under "Self-hosted". That
# server is VITE_SERVER_URL when it's set, as in the release workflow, then OCTAPASS_BUILD_SERVER_URL
# from the environment or the repository's .env.local, then a question in a terminal that offers
# pnpm start's public address. Without a terminal it's the hosted service. --setup asks again.
#
# Other arguments go to the app's own build, like --platform macos for build:safari or
# --target firefox for build:extension. The builds are unsigned unless the app's own signing
# settings are set (see each app's README). build:macos signs with the team the iPhone builds use,
# and needs one (apps/macos/scripts/build.sh).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/prompt.sh
source "$root/scripts/lib/prompt.sh"

app="${1:-}"
[[ $# -eq 0 ]] || shift
setup=false
rest=()
while (($#)); do
  case "$1" in
    --setup) setup=true ;;
    *) rest+=("$1") ;;
  esac
  shift
done
if $setup && ! can_ask; then
  echo "--setup asks questions, so it needs a terminal." >&2
  exit 2
fi

system="$(uname -s)"

# The server the build offers as "Octa Pass", exported for the app's build.
choose_server() {
  local server
  if $setup; then
    pick_build_server server ask
  else
    pick_build_server server
  fi
  if $PICK_BUILD_SERVER_ASKED && confirm "Save it in .env.local, so later builds don't ask?"; then
    save_env "$root/.env.local" OCTAPASS_BUILD_SERVER_URL "$server"
    echo "Saved; pnpm build:$app --setup asks again." >&2
  fi
  echo "\"Octa Pass\" on the sign-in screen: $server" >&2
  # VITE_SERVER_URL for the extensions and the desktop app, OCTAPASS_BUILD_SERVER_URL for the
  # iPhone and Android builds.
  export VITE_SERVER_URL="$server" OCTAPASS_BUILD_SERVER_URL="$server"
}

on_mac() {
  if [[ "$system" != Darwin ]]; then
    echo "pnpm build:$app needs a Mac (Xcode)." >&2
    exit 1
  fi
}

core() {
  pnpm --dir "$root" --filter @octapass/core build:if-stale
}

need_tauri() {
  if ! cargo tauri --version >/dev/null 2>&1; then
    echo "The desktop app needs the Tauri CLI: cargo install tauri-cli --locked --version 2.12.4" >&2
    exit 1
  fi
}

bundles() {
  echo "Built in apps/desktop/target/release/bundle/:" >&2
  (cd "$root/apps/desktop/target/release/bundle" 2>/dev/null && find . -maxdepth 2 -mindepth 2 \( -name '*.dmg' -o -name '*.app' -o -name '*.exe' -o -name '*.deb' -o -name '*.rpm' -o -name '*.AppImage' \) | sed 's#^\./#  #') >&2 || true
}

case "$app" in
  extension)
    choose_server
    core
    pnpm --dir "$root" --filter @octapass/extension build ${rest[@]+"${rest[@]}"}
    ;;
  safari)
    on_mac
    choose_server
    "$root/apps/safari/scripts/build.sh" ${rest[@]+"${rest[@]}"}
    ;;
  ios)
    on_mac
    choose_server
    "$root/apps/ios/scripts/build.sh" ${rest[@]+"${rest[@]}"}
    ;;
  android)
    choose_server
    "$root/scripts/android.sh" build
    ;;
  desktop)
    args=(${rest[@]+"${rest[@]}"})
    if $setup; then args+=(--setup); fi
    case "$system" in
      # On a Mac, Octa Pass is the native app (plan 19); the Tauri app is for Windows and Linux.
      Darwin) exec "$0" macos ${args[@]+"${args[@]}"} ;;
      Linux) exec "$0" linux ${args[@]+"${args[@]}"} ;;
      MINGW* | MSYS* | CYGWIN*) exec "$0" windows ${args[@]+"${args[@]}"} ;;
      *) echo "No desktop build for $system." >&2; exit 1 ;;
    esac
    ;;
  macos)
    # The native SwiftUI app (apps/macos, plan 19).
    on_mac
    choose_server
    "$root/apps/macos/scripts/build.sh" ${rest[@]+"${rest[@]}"}
    ;;
  windows)
    case "$system" in
      Darwin)
        need_tauri
        choose_server
        core
        "$root/apps/desktop/scripts/build-windows.sh"
        echo "Built in apps/desktop/target/x86_64-pc-windows-msvc/release/bundle/nsis/" >&2
        ;;
      MINGW* | MSYS* | CYGWIN*)
        need_tauri
        choose_server
        core
        (cd "$root/apps/desktop" && cargo tauri build --bundles nsis ${rest[@]+"${rest[@]}"})
        bundles
        ;;
      *)
        echo "Build the Windows installer on Windows, cross-compile it on a Mac, or use the release workflow (.github/workflows/release.yml)." >&2
        exit 1
        ;;
    esac
    ;;
  linux)
    if [[ "$system" != Linux ]]; then
      echo "Build the Linux packages on Linux, or use the release workflow (.github/workflows/release.yml)." >&2
      exit 1
    fi
    need_tauri
    choose_server
    core
    (cd "$root/apps/desktop" && cargo tauri build --bundles deb,rpm,appimage ${rest[@]+"${rest[@]}"})
    bundles
    ;;
  cli)
    cargo build --manifest-path "$root/Cargo.toml" --release -p octapass-cli ${rest[@]+"${rest[@]}"}
    echo "Built target/release/octapass, git-credential-octapass, octapass-git-sign and docker-credential-octapass" >&2
    ;;
  vscode)
    pnpm --dir "$root" --filter @octapass/vscode run stage
    version="$(cd "$root/apps/vscode" && node -p 'require("./package.json").version')"
    # VS Code's packaging tool, the way apps/vscode/README.md packages it.
    (cd "$root/apps/vscode/dist/stage" && npx --yes @vscode/vsce package --no-dependencies --out "../octapass-$version.vsix")
    echo "Built apps/vscode/dist/octapass-$version.vsix" >&2
    ;;
  jetbrains)
    (cd "$root/apps/jetbrains" && ./gradlew buildPlugin ${rest[@]+"${rest[@]}"})
    echo "Built in apps/jetbrains/plugin/build/distributions/" >&2
    ;;
  *)
    echo "usage: scripts/build-app.sh extension|safari|ios|android|desktop|macos|windows|linux|cli|vscode|jetbrains [--setup]" >&2
    exit 2
    ;;
esac
