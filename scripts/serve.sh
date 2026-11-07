#!/usr/bin/env bash
# The API and the web vault on one port: the same setup as deploy/octap.app, without Docker.
# The server serves apps/web/dist itself, so the web vault talks to the server it came from.
#
#   pnpm start            builds the web vault and the server, then serves them
#   pnpm start --setup    asks the questions below again, then builds and serves
#   pnpm serve            serves the last build (pnpm serve --setup asks again too)
#
# The first run in a terminal asks where people open Octa Pass and who can create an account, then
# offers to save the answers in the gitignored .env.local at the repository root. Without a
# terminal (or with OCTAPASS_NO_PROMPT=1) it uses the defaults below and prints them.
#
# Dev mode stays off, since the address can be public through a tunnel and dev mode would hand
# sign-up codes to anyone who asks. Without SMTP the codes are in this log.
#
# Settings, from the environment or .env.local (the environment wins):
#   OCTAPASS_PUBLIC_URL   where people open it (default https://pass.example.com, through a tunnel)
#   OCTAPASS_SIGNUPS      invite (default), open or closed
#   OCTAPASS_INVITES      emails that can sign up while it's invite, comma-separated (default your
#                         git email)
#   OCTAPASS_DATA_DIR     the vault data (default ~/.octapass-server, outside the repository)
#   OCTAPASS_BIND         default 127.0.0.1:8380, where the tunnel points
#   OCTAPASS_TRUST_PROXY  true (default) while a tunnel or proxy on this computer forwards to it
#   OCTAPASS_SMTP_URL, OCTAPASS_SMTP_FROM   real email instead of codes in this log
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
# shellcheck source=lib/prompt.sh
source "$root/scripts/lib/prompt.sh"

build=false
setup=false
while (($#)); do
  case "$1" in
    --build) build=true ;;
    --setup) setup=true ;;
    *) echo "usage: scripts/serve.sh [--build] [--setup]" >&2; exit 2 ;;
  esac
  shift
done

settings="$root/.env.local"
load_env "$settings"
export OCTAPASS_BIND="${OCTAPASS_BIND:-$SERVE_BIND_DEFAULT}"
local_url="http://localhost:${OCTAPASS_BIND##*:}"
git_email="$(git config user.email || true)"

if $setup && ! can_ask; then
  echo "--setup asks questions, so it needs a terminal." >&2
  exit 2
fi

# Where people open it.
asked_address=false
if can_ask && { $setup || ! is_set OCTAPASS_PUBLIC_URL; }; then
  asked_address=true
  current="${OCTAPASS_PUBLIC_URL:-$SERVE_PUBLIC_URL_DEFAULT}"
  tunnel="$current"
  is_localhost "$tunnel" && tunnel="$SERVE_PUBLIC_URL_DEFAULT"
  default=1
  is_localhost "$current" && default=2
  choose where "Where will people open Octa Pass?" "$default" \
    "Through a tunnel or proxy at $tunnel" \
    "Only on this computer, at $local_url" \
    "Through a tunnel or proxy at another address"
  case "$where" in
    1) OCTAPASS_PUBLIC_URL="$tunnel" OCTAPASS_TRUST_PROXY=true ;;
    2) OCTAPASS_PUBLIC_URL="$local_url" OCTAPASS_TRUST_PROXY=false ;;
    3) ask_url OCTAPASS_PUBLIC_URL "The public address" && OCTAPASS_TRUST_PROXY=true ;;
  esac
  # The web vault comes from the same address.
  OCTAPASS_WEB_ORIGINS="$OCTAPASS_PUBLIC_URL"
  export OCTAPASS_PUBLIC_URL OCTAPASS_TRUST_PROXY OCTAPASS_WEB_ORIGINS
  [[ "$where" == 2 ]] || echo "Point the tunnel or proxy at http://$OCTAPASS_BIND." >&2
fi
export OCTAPASS_PUBLIC_URL="${OCTAPASS_PUBLIC_URL:-$SERVE_PUBLIC_URL_DEFAULT}"

# Who can create an account.
asked_signups=false
if can_ask && { $setup || ! is_set OCTAPASS_SIGNUPS; }; then
  asked_signups=true
  case "${OCTAPASS_SIGNUPS:-invite}" in
    open) default=2 ;;
    closed) default=3 ;;
    *) default=1 ;;
  esac
  choose who "Who can create an account?" "$default" \
    "Only the emails you invite" \
    "Anyone who can open $OCTAPASS_PUBLIC_URL" \
    "No one new: only the accounts that already exist"
  case "$who" in
    1) OCTAPASS_SIGNUPS=invite ;;
    2) OCTAPASS_SIGNUPS=open ;;
    3) OCTAPASS_SIGNUPS=closed ;;
  esac
  export OCTAPASS_SIGNUPS
  if [[ "$OCTAPASS_SIGNUPS" == open ]] && ! is_localhost "$OCTAPASS_PUBLIC_URL"; then
    echo "Anyone who finds $OCTAPASS_PUBLIC_URL can then create an account and store data on this computer." >&2
  fi
fi
export OCTAPASS_SIGNUPS="${OCTAPASS_SIGNUPS:-invite}"

asked_invites=false
invites_from=""
if [[ "$OCTAPASS_SIGNUPS" == invite ]]; then
  if can_ask && { $setup || $asked_signups || ! is_set OCTAPASS_INVITES; }; then
    asked_invites=true
    suggested="${OCTAPASS_INVITES:-$git_email}"
    while true; do
      ask invites "Emails that can sign up, separated by commas" "$suggested"
      invites="$(printf '%s' "$invites" | tr -d '[:space:]')"
      bad="$(printf '%s' "$invites" | tr ',' '\n' | grep -v -E '^$|^[^@]+@[^@]+$' || true)"
      [[ -z "$bad" ]] && break
      echo "Not an email: $(printf '%s' "$bad" | head -1)" >&2
    done
    OCTAPASS_INVITES="$invites"
  elif ! is_set OCTAPASS_INVITES; then
    OCTAPASS_INVITES="$git_email"
    invites_from=" (your git email)"
  fi
  export OCTAPASS_INVITES
fi

if $asked_address || $asked_signups || $asked_invites; then
  if confirm "Save these answers in .env.local, so the next run doesn't ask?"; then
    if $asked_address; then
      save_env "$settings" OCTAPASS_PUBLIC_URL "$OCTAPASS_PUBLIC_URL"
      save_env "$settings" OCTAPASS_TRUST_PROXY "$OCTAPASS_TRUST_PROXY"
      [[ -z "$(env_file_value "$settings" OCTAPASS_WEB_ORIGINS)" ]] || save_env "$settings" OCTAPASS_WEB_ORIGINS "$OCTAPASS_WEB_ORIGINS"
    fi
    $asked_signups && save_env "$settings" OCTAPASS_SIGNUPS "$OCTAPASS_SIGNUPS"
    $asked_invites && save_env "$settings" OCTAPASS_INVITES "$OCTAPASS_INVITES"
    echo "Saved in .env.local; pnpm start --setup asks again." >&2
  fi
fi

if $build; then
  pnpm build:web
  pnpm build:api
fi
if [[ ! -f apps/web/dist/index.html || ! -x target/release/octapass-server ]]; then
  echo "Run pnpm build:web and pnpm build:api first, or use pnpm start." >&2
  exit 1
fi

export OCTAPASS_WEB_ORIGINS="${OCTAPASS_WEB_ORIGINS:-$OCTAPASS_PUBLIC_URL}"
export OCTAPASS_WEB_DIR="${OCTAPASS_WEB_DIR:-$root/apps/web/dist}"
export OCTAPASS_DATA_DIR="${OCTAPASS_DATA_DIR:-$HOME/.octapass-server}"
# The tunnel is the proxy. Safe while the bind address stays on 127.0.0.1.
export OCTAPASS_TRUST_PROXY="${OCTAPASS_TRUST_PROXY:-true}"
if [[ -z "${OCTAPASS_SMTP_URL:-}" ]]; then
  export OCTAPASS_EMAIL_TO_LOG="${OCTAPASS_EMAIL_TO_LOG:-true}"
fi
mkdir -p "$OCTAPASS_DATA_DIR"

if is_localhost "$OCTAPASS_PUBLIC_URL"; then
  address="$OCTAPASS_PUBLIC_URL, on this computer only"
else
  address="$OCTAPASS_PUBLIC_URL, forwarded to http://$OCTAPASS_BIND"
fi
case "$OCTAPASS_SIGNUPS" in
  open) signups="anyone who can open the address" ;;
  closed) signups="no one new" ;;
  *)
    if [[ -n "${OCTAPASS_INVITES:-}" ]]; then
      signups="only invited emails: $OCTAPASS_INVITES$invites_from"
    else
      signups="only invited emails, and none are invited (set OCTAPASS_INVITES)"
    fi
    ;;
esac
if [[ -n "${OCTAPASS_SMTP_URL:-}" ]]; then
  email="sent through OCTAPASS_SMTP_URL"
else
  email="codes appear in this log (set OCTAPASS_SMTP_URL to send real email)"
fi
cat <<SUMMARY
Octa Pass
  Address   $address
  Sign-ups  $signups
  Email     $email
  Data      $OCTAPASS_DATA_DIR
Change these with pnpm start --setup, or in .env.local.
SUMMARY
exec target/release/octapass-server
