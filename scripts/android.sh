#!/usr/bin/env bash
# The native Android app.
#
#   scripts/android.sh dev [--setup]   installs a debug build on an emulator or phone
#   scripts/android.sh build           an unsigned release build, offering OCTAPASS_BUILD_SERVER_URL
#                                      (pnpm build:android picks it) or the hosted server
#
# dev picks the device and the server, and asks only when it can't tell (always with --setup):
#   the device   ANDROID_SERIAL, else the only one `adb devices` lists, else a choice
#   the server   OCTAPASS_SERVER_URL, else whichever of pnpm dev:api (port 8080) and pnpm start
#                runs on this computer, reached through adb reverse, else a choice. pnpm start's
#                public address works too, with no adb reverse. OCTAPASS_DEV_PORT=8097 still
#                means http://localhost:8097.
#
# Needs Java 17, ANDROID_HOME with the SDK and NDK, and the Rust Android targets.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
library="$root/apps/android/vault/jniLibs/arm64-v8a/liboctapass_mobile.so"
# shellcheck source=lib/prompt.sh
source "$root/scripts/lib/prompt.sh"
# shellcheck source=lib/stale.sh
source "$root/scripts/lib/stale.sh"

# The app's Rust library, rebuilt when its sources change (the Kotlin bindings change with them).
ensure_library() {
  rebuild_if_stale octapass-mobile "$library" "$root/crates/octapass-mobile/scripts/build-android.sh" \
    "$root/crates/octapass-mobile/scripts/common.sh"
}

case "${1:-}" in
  dev)
    setup=false
    [[ "${2:-}" == --setup ]] && setup=true
    if $setup && ! can_ask; then
      echo "--setup asks questions, so it needs a terminal." >&2
      exit 2
    fi
    adb="${ANDROID_HOME:?set ANDROID_HOME}/platform-tools/adb"

    # The device.
    if [[ -z "${ANDROID_SERIAL:-}" ]] || $setup; then
      serials=() labels=() ready=0 unauthorized=0
      while read -r serial state rest; do
        case "$state" in
          device)
            model="$(printf '%s\n' "$rest" | tr ' ' '\n' | sed -n 's/^model://p' | tr '_' ' ')"
            serials[ready]="$serial"
            labels[ready]="${model:-$serial} ($serial)"
            ready=$((ready + 1))
            ;;
          unauthorized) unauthorized=$((unauthorized + 1)) ;;
        esac
      done < <("$adb" devices -l | tail -n +2)
      if [[ $ready -eq 0 ]]; then
        if ((unauthorized)); then
          echo "Allow USB debugging on the phone (a prompt on its screen), then try again." >&2
        else
          echo "No emulator or phone is connected. Start an emulator (Android Studio > Device Manager) or connect a phone with USB debugging on." >&2
        fi
        exit 1
      elif [[ $ready -eq 1 ]] && ! $setup; then
        ANDROID_SERIAL="${serials[0]}"
      elif can_ask; then
        default=1
        for ((i = 0; i < ready; i++)); do
          [[ "${serials[i]}" != "${ANDROID_SERIAL:-}" ]] || default=$((i + 1))
        done
        choose pick "Which device should the app go on?" "$default" "${labels[@]}"
        ANDROID_SERIAL="${serials[pick - 1]}"
      else
        echo "Several devices are connected; set ANDROID_SERIAL to one of: ${serials[*]}" >&2
        exit 1
      fi
    fi
    # adb and Gradle's install task both read it.
    export ANDROID_SERIAL

    # The server.
    if [[ -n "${OCTAPASS_DEV_PORT:-}" ]]; then
      server="http://localhost:$OCTAPASS_DEV_PORT"
    elif $setup; then
      pick_server server local ask
    else
      pick_server server local
    fi
    if is_localhost "$server"; then
      address="${server#*://}"
      address="${address%%/*}"
      port="${address##*:}"
      [[ "$port" != "$address" ]] || port=80
      "$adb" reverse "tcp:$port" "tcp:$port" >/dev/null
    fi

    ensure_library
    echo "Installing on $ANDROID_SERIAL, using the server $server" >&2
    cd "$root/apps/android"
    ./gradlew :app:installDebug "-PoctapassServer=$server"
    ;;
  build)
    ensure_library
    cd "$root/apps/android"
    # The "Octa Pass" server choice (pnpm build:android picks it); without it, the hosted service.
    if [[ -n "${OCTAPASS_BUILD_SERVER_URL:-}" ]]; then
      ./gradlew :app:assembleRelease "-PoctapassServer=$OCTAPASS_BUILD_SERVER_URL"
    else
      ./gradlew :app:assembleRelease
    fi
    echo "Built apps/android/app/build/outputs/apk/release"
    ;;
  *)
    echo "usage: scripts/android.sh dev [--setup] | build" >&2
    exit 2
    ;;
esac
