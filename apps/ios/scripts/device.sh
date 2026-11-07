#!/usr/bin/env bash
# Builds the app and its AutoFill extension for a connected iPhone or iPad, installs it and
# launches it.
#
#   pnpm dev:ios:device            asks for what it can't work out, the first time
#   pnpm dev:ios:device --setup    asks every question again
#
# Each setting comes from the environment, then the gitignored apps/ios/device.env, then a question
# when there's a terminal. The answers can be saved in device.env.
#   APPLE_DEVELOPMENT_TEAM  the team that signs the app. The choices are the teams of the accounts
#                           signed in to Xcode and of the Apple Development certificates in the
#                           keychain. It goes into the gitignored Signing.local.xcconfig, which
#                           every target signs with and which later runs reuse, so no team ID is
#                           committed.
#   DEVICE                  a name or identifier from `xcrun devicectl list devices`. Without it:
#                           the only connected iPhone or iPad, or a choice between them.
#   OCTAPASS_SERVER_URL     the server the app signs in to. A phone can't reach this Mac's
#                           localhost, so the choice is pnpm start's public address or another.
source "$(dirname "$0")/common.sh"

setup=false
while (($#)); do
  case "$1" in
    --setup) setup=true ;;
    *) echo "usage: apps/ios/scripts/device.sh [--setup]" >&2; exit 2 ;;
  esac
  shift
done
if $setup && ! can_ask; then
  echo "--setup asks questions, so it needs a terminal." >&2
  exit 2
fi
settings="$IOS/device.env"
load_env "$settings"
save_team="" save_device="" save_server=""
scratch="$(mktemp -d "${TMPDIR:-/tmp}/octapass-device.XXXXXX")"
cleanup+=("rm -rf '$scratch'")

# The teams this Mac can sign with, one "ID<tab>name" line each: the accounts signed in to Xcode,
# then the Apple Development certificates in the keychain (a certificate's OU is its team).
list_teams() {
  defaults export com.apple.dt.Xcode "$scratch/xcode.plist" 2>/dev/null || : >"$scratch/xcode.plist"
  {
    security find-identity -v -p codesigning \
      | sed -E -n 's/^.*"((Apple Development|iPhone Developer): .*)"$/\1/p' \
      | while IFS= read -r identity; do
          security find-certificate -c "$identity" -p | openssl x509 -noout -subject || true
        done
  } >"$scratch/certificates.txt" 2>/dev/null || true
  python3 -I - "$scratch/xcode.plist" "$scratch/certificates.txt" <<'PY'
import plistlib, re, sys

teams = {}

def add(team_id, name):
    if team_id and team_id not in teams:
        teams[team_id] = name

def walk(node):
    if isinstance(node, dict):
        if "teamID" in node:
            yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)

try:
    with open(sys.argv[1], "rb") as f:
        prefs = plistlib.load(f)
except Exception:
    prefs = {}
# IDEProvisioningTeams before Xcode 16, IDEProvisioningTeamByIdentifier since.
for key, value in prefs.items():
    if key.startswith("IDEProvisioningTeam"):
        for team in walk(value):
            name = team.get("teamName") or ""
            # Xcode names a free team "Name (Personal Team)" already.
            if team.get("isFreeProvisioningTeam") and "Personal Team" not in name:
                name += " (Personal Team)"
            add(str(team["teamID"]), name)
# "subject= /UID=…/CN=…/OU=TEAMID/O=Name/C=US" (LibreSSL) or "subject=UID = …, OU = TEAMID, O = Name" (OpenSSL 3).
for line in open(sys.argv[2], errors="replace"):
    unit = re.search(r"\bOU\s*=\s*([A-Z0-9]{10})\b", line)
    org = re.search(r"(?:^|[/,])\s*O\s*=\s*([^,/]+)", line)
    if unit:
        add(unit.group(1), org.group(1).strip() if org else "")
for team_id, name in teams.items():
    print(team_id + "\t" + name)
PY
}

# ask_team NAME [DEFAULT]: a team ID typed in.
ask_team() {
  local typed
  while true; do
    ask typed "Team ID, 10 letters and digits (developer.apple.com/account, under Membership)" "${2:-}"
    typed="$(printf '%s' "$typed" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
    [[ ${#typed} -eq 10 && $typed != *[!A-Z0-9]* ]] && break
    echo "A team ID is 10 letters and digits, like A1B2C3D4E5." >&2
  done
  printf -v "$1" '%s' "$typed"
}

# The iPhones and iPads devicectl can install on, one line each of "identifier<tab>UDID<tab>name
# <tab>label<tab>Developer Mode". A function, because macOS's bash 3.2 can't parse a here-document
# inside <(…) when its text holds an apostrophe.
list_devices() {
  python3 -I - "$1" <<'PY'
import json, sys
for d in json.load(open(sys.argv[1]))["result"]["devices"]:
    props, hw, conn = d.get("deviceProperties", {}), d.get("hardwareProperties", {}), d.get("connectionProperties", {})
    if hw.get("deviceType") not in ("iPhone", "iPad"):
        continue
    # "disconnected" is a paired phone nearby that devicectl connects to on demand.
    if conn.get("tunnelState") not in ("connected", "disconnected"):
        continue
    model = hw.get("marketingName") or hw.get("deviceType")
    name = props.get("name") or model
    link = {"wired": "cable", "localNetwork": "Wi-Fi"}.get(conn.get("transportType"), "nearby")
    # No empty fields: read joins consecutive tabs.
    print("\t".join([d["identifier"], hw.get("udid") or "-", name, name + " (" + model + ", " + link + ")", props.get("developerModeStatus") or "-"]))
PY
}

# --- The team.
saved_team="$(sed -n 's/^DEVELOPMENT_TEAM = //p' "$IOS/Signing.local.xcconfig" 2>/dev/null || true)"
team="${APPLE_DEVELOPMENT_TEAM:-$saved_team}"
if [[ -z "$team" ]] || $setup; then
  team_ids=() team_labels=() teams=0
  while IFS=$'\t' read -r id name; do
    [[ -n "$id" ]] || continue
    team_ids[teams]="$id"
    team_labels[teams]="${name:-Team} ($id)"
    teams=$((teams + 1))
  done < <(list_teams)
  if ! $setup && [[ $teams -eq 1 ]]; then
    team="${team_ids[0]}"
    echo "Signing with ${team_labels[0]}, the only team on this Mac." >&2
  elif can_ask; then
    if [[ $teams -eq 0 ]]; then
      echo "No signing team found on this Mac. Sign in to Xcode with your Apple Account (Xcode > Settings > Accounts) to list yours here, or type the team ID." >&2
      ask_team team "$team"
    else
      default=1
      for ((i = 0; i < teams; i++)); do
        [[ "${team_ids[i]}" == "$team" ]] && default=$((i + 1))
      done
      choose pick "Which team signs the app?" "$default" ${team_labels[@]+"${team_labels[@]}"} "Type a team ID"
      if ((pick <= teams)); then
        team="${team_ids[pick - 1]}"
      else
        ask_team team "$team"
      fi
    fi
    save_team="$team"
  else
    echo "Set APPLE_DEVELOPMENT_TEAM (your Apple team ID) or put it in apps/ios/device.env, or run this in a terminal to pick one." >&2
    if ((teams)); then
      echo "Teams on this Mac:" >&2
      printf '  %s\n' "${team_labels[@]}" >&2
    fi
    exit 1
  fi
fi

# --- The device.
xcrun devicectl list devices --json-output "$scratch/devices.json" >/dev/null
device_ids=() device_names=() device_labels=() device_modes=() devices=0 match=0
while IFS=$'\t' read -r id udid name label mode; do
  device_ids[devices]="$id"
  device_names[devices]="$name"
  device_labels[devices]="$label"
  device_modes[devices]="$mode"
  devices=$((devices + 1))
  if [[ -n "${DEVICE:-}" && ( "$DEVICE" == "$id" || "$DEVICE" == "$udid" || "$DEVICE" == "$name" ) ]]; then
    match=$devices
  fi
done < <(list_devices "$scratch/devices.json")
if [[ $devices -eq 0 ]]; then
  echo "No iPhone or iPad is connected. Connect one with a cable, unlock it and tap Trust, then try again (see xcrun devicectl list devices)." >&2
  exit 1
fi
if ((match)) && ! $setup; then
  pick=$match
elif [[ -z "${DEVICE:-}" && $devices -eq 1 ]] && ! $setup; then
  pick=1
else
  [[ -z "${DEVICE:-}" ]] || ((match)) || echo "DEVICE=$DEVICE isn't connected." >&2
  if can_ask; then
    choose pick "Which device should the app go on?" "$((match ? match : 1))" "${device_labels[@]}"
    # Remembered when there was a real choice, or in place of a DEVICE that isn't connected.
    [[ $devices -eq 1 && -z "${DEVICE:-}" ]] || save_device="${device_names[pick - 1]}"
  elif [[ -n "${DEVICE:-}" ]]; then
    echo "Connected:" >&2
    printf '  %s\n' "${device_labels[@]}" >&2
    exit 1
  else
    pick=1
    echo "Several devices are connected; using ${device_names[0]}. Set DEVICE to pick another." >&2
  fi
fi
device="${device_ids[pick - 1]}"
if [[ "${device_modes[pick - 1]}" == disabled ]]; then
  echo "Turn on Developer Mode on ${device_names[pick - 1]} (Settings > Privacy & Security > Developer Mode) if the install is refused." >&2
fi

# --- The server.
if $setup; then
  pick_server server phone ask
else
  pick_server server phone
fi
$PICK_SERVER_ASKED && save_server="$server"
if is_localhost "$server"; then
  echo "A phone can't reach $server on this Mac. Use pnpm start's public address, or this Mac's network address." >&2
fi

if [[ -n "$save_team$save_device$save_server" ]] && confirm "Save these answers in apps/ios/device.env, so the next run doesn't ask?"; then
  [[ -z "$save_team" ]] || save_env "$settings" APPLE_DEVELOPMENT_TEAM "$save_team"
  [[ -z "$save_device" ]] || save_env "$settings" DEVICE "$save_device"
  [[ -z "$save_server" ]] || save_env "$settings" OCTAPASS_SERVER_URL "$save_server"
  echo "Saved; pnpm dev:ios:device --setup asks again." >&2
fi

printf 'DEVELOPMENT_TEAM = %s\n' "$team" >"$IOS/Signing.local.xcconfig"
echo "Building for ${device_labels[pick - 1]}, signed by team $team, using the server $server" >&2
ensure_vault_framework
ensure_project
xcode device build -project "$IOS/OctaPass.xcodeproj" -scheme OctaPass -configuration Debug \
  -destination "generic/platform=iOS" -derivedDataPath "$DERIVED" -allowProvisioningUpdates \
  "OCTAPASS_SERVER_URL=$server"
app="$DERIVED/Build/Products/Debug-iphoneos/Octa Pass.app"
xcrun devicectl device install app --device "$device" "$app"
xcrun devicectl device process launch --device "$device" app.octap.ios || echo "Installed; unlock the phone and open Octa Pass."
echo "Installed $app on ${device_names[pick - 1]}"
