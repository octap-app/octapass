#!/usr/bin/env bash
# Builds the app, installs it on the Simulator and launches it.
#
#   pnpm dev:ios            picks the Simulator and the server, asking only when it can't tell
#   pnpm dev:ios --setup    asks both questions
#
# The Simulator: DEVICE (a name or identifier from `xcrun simctl list devices`), else the one
# that's booted, else a choice (iPhone 17 Pro without a terminal). A Simulator left booted is
# picked again next time.
# The server: OCTAPASS_SERVER_URL, else whichever of pnpm dev:api (http://localhost:8080) and
# pnpm start runs on this Mac, else a choice.
source "$(dirname "$0")/common.sh"

setup=false
while (($#)); do
  case "$1" in
    --setup) setup=true ;;
    *) echo "usage: apps/ios/scripts/simulator.sh [--setup]" >&2; exit 2 ;;
  esac
  shift
done
if $setup && ! can_ask; then
  echo "--setup asks questions, so it needs a terminal." >&2
  exit 2
fi

# The iPhone and iPad Simulators, one line each of "identifier<tab>name<tab>iOS version<tab>state",
# newest iOS first. A function, because macOS's bash 3.2 can't reliably parse a here-document
# inside <(…).
list_simulators() {
  python3 -I - "$1" <<'PY'
import json, re, sys
rows = []
for runtime, devices in json.load(open(sys.argv[1])).get("devices", {}).items():
    version = re.search(r"SimRuntime\.iOS-(\d+)-(\d+)$", runtime)
    if not version:
        continue
    for d in devices:
        if d.get("isAvailable", True) and d.get("name", "").startswith(("iPhone", "iPad")):
            rows.append(((int(version.group(1)), int(version.group(2))), d))
# Newest iOS first, then iPhones before iPads.
rows.sort(key=lambda row: (-row[0][0], -row[0][1], not row[1]["name"].startswith("iPhone"), row[1]["name"]))
for (major, minor), d in rows:
    print("\t".join([d["udid"], d["name"], "%d.%d" % (major, minor), d.get("state") or "-"]))
PY
}

# --- The Simulator.
simulators="$(mktemp "${TMPDIR:-/tmp}/octapass-simulators.XXXXXX")"
cleanup+=("rm -f '$simulators'")
xcrun simctl list devices available -j >"$simulators"
sim_ids=() sim_names=() sim_labels=() sims=0 booted=0 booted_count=0 match=0 fallback=0 newest=""
while IFS=$'\t' read -r id name version state; do
  [[ -n "$newest" ]] || newest="$version"
  wanted=false
  [[ -n "${DEVICE:-}" && ( "$DEVICE" == "$id" || "$DEVICE" == "$name" ) ]] && wanted=true
  # The choices: the newest iOS, any Simulator that's booted, and the one DEVICE names.
  [[ "$version" == "$newest" || "$state" == Booted ]] || $wanted || continue
  sim_ids[sims]="$id"
  sim_names[sims]="$name"
  sim_labels[sims]="$name, iOS $version"
  sims=$((sims + 1))
  if [[ "$state" == Booted ]]; then
    sim_labels[sims - 1]="${sim_labels[sims - 1]} (booted)"
    booted_count=$((booted_count + 1))
    ((booted)) || booted=$sims
  fi
  if $wanted && ((!match)); then
    match=$sims
  fi
  [[ "$name" != "$DEFAULT_SIMULATOR" ]] || ((fallback)) || fallback=$sims
done < <(list_simulators "$simulators")
if [[ $sims -eq 0 ]]; then
  echo "No iPhone or iPad Simulator is installed. Add one in Xcode (Window > Devices and Simulators)." >&2
  exit 1
fi
if ((match)) && ! $setup; then
  pick=$match
elif [[ -z "${DEVICE:-}" && $booted_count -eq 1 ]] && ! $setup; then
  pick=$booted
else
  [[ -z "${DEVICE:-}" ]] || ((match)) || echo "No Simulator named $DEVICE." >&2
  default=$((match ? match : booted ? booted : fallback ? fallback : 1))
  if can_ask; then
    choose pick "Which Simulator?" "$default" "${sim_labels[@]}"
  elif [[ -n "${DEVICE:-}" ]]; then
    echo "Simulators on this Mac:" >&2
    printf '  %s\n' "${sim_labels[@]}" >&2
    exit 1
  else
    pick=$default
  fi
fi
simulator="${sim_ids[pick - 1]}"

# --- The server.
if $setup; then
  pick_server server local ask
else
  pick_server server local
fi

echo "Building for ${sim_labels[pick - 1]}, using the server $server" >&2
ensure_vault_framework
ensure_project
xcrun simctl boot "$simulator" 2>/dev/null || true
open -a Simulator
xcode simulator build -project "$IOS/OctaPass.xcodeproj" -scheme OctaPass -configuration Debug \
  -destination "platform=iOS Simulator,id=$simulator" -derivedDataPath "$DERIVED" \
  "OCTAPASS_SERVER_URL=$server"
app="$DERIVED/Build/Products/Debug-iphonesimulator/Octa Pass.app"
xcrun simctl install "$simulator" "$app"
xcrun simctl launch "$simulator" app.octap.ios
echo "Running on ${sim_names[pick - 1]}, using the server $server"
