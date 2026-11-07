# Shared by the development scripts (pnpm start, dev:ios, dev:ios:device, dev:android): questions
# with a default answer, settings remembered in a gitignored file, and which local servers are
# running. Source it, don't run it.
#
# Written for the bash 3.2 that ships with macOS: no associative arrays, and never "${list[@]}" on
# a list that may be empty, which `set -u` treats as an unset variable there.
#
# Nothing is asked without a terminal (CI, pipes) or with OCTAPASS_NO_PROMPT=1: the scripts then
# use their defaults and say which.

OCTAPASS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# pnpm start's defaults (scripts/serve.sh), which pick_server offers too.
SERVE_BIND_DEFAULT="127.0.0.1:8380"
SERVE_PUBLIC_URL_DEFAULT="https://pass.example.com"
# pnpm dev:api.
DEV_API_URL="http://localhost:8080"
# The hosted service, the apps' built-in "Octa Pass" server (packages/vault-client/src/serverUrl.ts).
HOSTED_SERVER_URL="https://vault.octap.app"

# Succeeds when there's someone to ask.
can_ask() {
  [[ -t 0 && -t 2 && -z "${OCTAPASS_NO_PROMPT:-}" && -z "${CI:-}" ]]
}

# Succeeds when the variable NAME is set, even to nothing.
is_set() {
  eval "[[ -n \${$1+set} ]]"
}

# choose NAME "Question" DEFAULT "Option 1" "Option 2"…
# Lists the options and sets NAME to the number picked, from 1. Enter picks DEFAULT.
choose() {
  local _ch_name=$1 _ch_question=$2 _ch_default=$3 _ch_answer _ch_i=1 _ch_option
  shift 3
  printf '\n%s\n' "$_ch_question" >&2
  for _ch_option in "$@"; do
    printf '  %d) %s\n' "$_ch_i" "$_ch_option" >&2
    _ch_i=$((_ch_i + 1))
  done
  while true; do
    read -r -p "Choose 1-$# [$_ch_default]: " _ch_answer || exit 1
    _ch_answer=${_ch_answer:-$_ch_default}
    if [[ $_ch_answer == [0-9]* && $_ch_answer != *[!0-9]* ]] && ((10#$_ch_answer >= 1 && 10#$_ch_answer <= $#)); then
      printf -v "$_ch_name" '%s' "$((10#$_ch_answer))"
      return 0
    fi
    printf 'Type a number from 1 to %d.\n' "$#" >&2
  done
}

# ask NAME "Question" [DEFAULT]: a line of text. Enter keeps DEFAULT.
ask() {
  local _as_name=$1 _as_question=$2 _as_default=${3:-} _as_answer
  if [[ -n $_as_default ]]; then
    read -r -p "$_as_question [$_as_default]: " _as_answer || exit 1
  else
    read -r -p "$_as_question: " _as_answer || exit 1
  fi
  printf -v "$_as_name" '%s' "${_as_answer:-$_as_default}"
}

# confirm "Question" [y|n]: succeeds on yes. Enter takes the default, yes unless "n".
confirm() {
  local _cf_answer _cf_default=${2:-y} _cf_hint='[Y/n]'
  [[ $_cf_default == n ]] && _cf_hint='[y/N]'
  read -r -p "$1 $_cf_hint " _cf_answer || exit 1
  [[ ${_cf_answer:-$_cf_default} == [Yy]* ]]
}

# env_file_value FILE NAME: the value FILE (a shell file of NAME=value lines) gives NAME, ignoring
# the environment.
env_file_value() {
  [[ -f $1 ]] || return 0
  (
    unset "$2"
    set +eu
    # shellcheck disable=SC1090
    . "$1" >/dev/null 2>&1
    eval "printf '%s' \"\${$2-}\""
  )
}

# load_env FILE: exports each NAME=value in FILE whose NAME isn't set yet, so a variable given on
# the command line wins over the file.
load_env() {
  local _le_file=$1 _le_name
  [[ -f $_le_file ]] || return 0
  for _le_name in $(sed -n 's/^[[:space:]]*\(export[[:space:]][[:space:]]*\)\{0,1\}\([A-Za-z_][A-Za-z0-9_]*\)=.*/\2/p' "$_le_file" | sort -u); do
    is_set "$_le_name" && continue
    export "$_le_name=$(env_file_value "$_le_file" "$_le_name")"
  done
}

# save_env FILE NAME VALUE: writes NAME=VALUE into FILE, in place of an earlier line for NAME.
# The file is readable by its owner only, since .env.local can hold an SMTP password.
save_env() {
  local _se_file=$1 _se_name=$2 _se_value=$3 _se_tmp
  _se_tmp="$(mktemp "$_se_file.XXXXXX")"
  if [[ -f $_se_file ]]; then
    grep -v -E "^[[:space:]]*(export[[:space:]]+)?$_se_name=" "$_se_file" >"$_se_tmp" || true
  else
    printf '# Local settings for the development scripts. Gitignored; edit or delete freely.\n' >"$_se_tmp"
  fi
  if [[ $_se_value == *\'* ]]; then
    printf '%s=%q\n' "$_se_name" "$_se_value" >>"$_se_tmp"
  else
    printf "%s='%s'\n" "$_se_name" "$_se_value" >>"$_se_tmp"
  fi
  mv "$_se_tmp" "$_se_file"
}

# serve_setting NAME DEFAULT: one of pnpm start's settings, from the environment, then the
# repository's .env.local, then DEFAULT.
serve_setting() {
  local _ss_value=
  if is_set "$1"; then
    eval "_ss_value=\${$1}"
  else
    _ss_value="$(env_file_value "$OCTAPASS_ROOT/.env.local" "$1")"
  fi
  printf '%s' "${_ss_value:-$2}"
}

# Succeeds when an Octa Pass server answers at the URL.
answers() {
  curl -sf --max-time 3 "${1%/}/v1/server-info" >/dev/null 2>&1
}

# Succeeds when the URL is this computer's own address, which a phone can't reach.
is_localhost() {
  local _il_pattern='^https?://(localhost|127\.[0-9.]+|\[::1\])(:|/|$)'
  [[ $1 =~ $_il_pattern ]]
}

# ask_url NAME "Question" [DEFAULT]: an http:// or https:// address, without a trailing slash.
ask_url() {
  local _au_name=$1 _au_url _au_pattern='^https?://[^[:space:]/]+'
  while true; do
    ask _au_url "$2" "${3:-}"
    if [[ $_au_url =~ $_au_pattern ]]; then
      printf -v "$_au_name" '%s' "${_au_url%/}"
      return 0
    fi
    echo "Type an address that starts with http:// or https://." >&2
  done
}

# pick_server NAME local|phone [ask]
# Sets NAME to the server a development build of the iPhone or Android app signs in to. That's
# OCTAPASS_SERVER_URL when it's set. Otherwise it's the one running among pnpm dev:api and pnpm
# start on this computer (for "local" only: the Simulator and adb reverse reach this computer's
# localhost, a phone over Wi-Fi doesn't) and pnpm start's public address. It asks when none or
# several of them are running, or always with "ask", and then sets PICK_SERVER_ASKED=true.
PICK_SERVER_ASKED=false
pick_server() {
  local _ps_name=$1 _ps_where=$2 _ps_force=${3:-} _ps_port _ps_public _ps_i _ps_n=0 _ps_running=0 _ps_first=0 _ps_pick _ps_url
  local -a _ps_urls _ps_labels
  if [[ -n ${OCTAPASS_SERVER_URL:-} && -z $_ps_force ]]; then
    printf -v "$_ps_name" '%s' "${OCTAPASS_SERVER_URL%/}"
    return 0
  fi
  _ps_port="$(serve_setting OCTAPASS_BIND "$SERVE_BIND_DEFAULT")"
  _ps_port=${_ps_port##*:}
  _ps_public="$(serve_setting OCTAPASS_PUBLIC_URL "$SERVE_PUBLIC_URL_DEFAULT")"
  _ps_public=${_ps_public%/}
  if [[ $_ps_where == local ]]; then
    _ps_urls[_ps_n]=$DEV_API_URL
    _ps_labels[_ps_n]="pnpm dev:api on this computer, $DEV_API_URL"
    _ps_n=$((_ps_n + 1))
    _ps_urls[_ps_n]="http://localhost:$_ps_port"
    _ps_labels[_ps_n]="pnpm start on this computer, http://localhost:$_ps_port"
    _ps_n=$((_ps_n + 1))
  fi
  if ! is_localhost "$_ps_public"; then
    _ps_urls[_ps_n]=$_ps_public
    _ps_labels[_ps_n]="pnpm start at its public address, $_ps_public"
    _ps_n=$((_ps_n + 1))
  fi
  for ((_ps_i = 0; _ps_i < _ps_n; _ps_i++)); do
    if answers "${_ps_urls[_ps_i]}"; then
      _ps_labels[_ps_i]="${_ps_labels[_ps_i]} (running)"
      _ps_running=$((_ps_running + 1))
      ((_ps_first)) || _ps_first=$((_ps_i + 1))
    else
      _ps_labels[_ps_i]="${_ps_labels[_ps_i]} (not answering now)"
    fi
  done

  if [[ -z $_ps_force && $_ps_running -eq 1 ]]; then
    printf -v "$_ps_name" '%s' "${_ps_urls[_ps_first - 1]}"
    return 0
  fi
  if ! can_ask; then
    if ((_ps_first)); then
      printf -v "$_ps_name" '%s' "${_ps_urls[_ps_first - 1]}"
    elif ((_ps_n)); then
      printf -v "$_ps_name" '%s' "${_ps_urls[0]}"
      echo "No Octa Pass server answers at ${_ps_urls[0]} yet; the app will use it once it does." >&2
    else
      echo "Set OCTAPASS_SERVER_URL to the server the app should sign in to." >&2
      exit 1
    fi
    return 0
  fi
  PICK_SERVER_ASKED=true
  choose _ps_pick "Which server should the app sign in to?" "$((_ps_first ? _ps_first : 1))" \
    ${_ps_labels[@]+"${_ps_labels[@]}"} "Another address"
  if ((_ps_pick <= _ps_n)); then
    _ps_url=${_ps_urls[_ps_pick - 1]}
  else
    ask_url _ps_url "Server address, like https://vault.example.com"
  fi
  answers "$_ps_url" || echo "No Octa Pass server answers at $_ps_url yet; start it before you sign in." >&2
  printf -v "$_ps_name" '%s' "$_ps_url"
}

# pick_build_server NAME [ask]
# Sets NAME to the server a build of the apps offers as "Octa Pass" on its sign-in screen (anyone
# can still type another under "Self-hosted"). That's VITE_SERVER_URL when it's set, as the release
# workflow does, then OCTAPASS_BUILD_SERVER_URL from the environment or .env.local, then a
# question that offers pnpm start's public address. Without a terminal it's the hosted service, as
# before. With "ask" it asks even when a server is saved, and after asking it sets
# PICK_BUILD_SERVER_ASKED=true.
PICK_BUILD_SERVER_ASKED=false
pick_build_server() {
  local _pb_name=$1 _pb_force=${2:-} _pb_saved _pb_public _pb_i _pb_n=0 _pb_default=0 _pb_running=0 _pb_pick _pb_url
  local -a _pb_urls _pb_labels
  if [[ -n ${VITE_SERVER_URL:-} ]]; then
    printf -v "$_pb_name" '%s' "${VITE_SERVER_URL%/}"
    return 0
  fi
  _pb_saved="$(serve_setting OCTAPASS_BUILD_SERVER_URL "")"
  _pb_saved=${_pb_saved%/}
  if [[ -n $_pb_saved && -z $_pb_force ]]; then
    printf -v "$_pb_name" '%s' "$_pb_saved"
    return 0
  fi
  if ! can_ask; then
    printf -v "$_pb_name" '%s' "$HOSTED_SERVER_URL"
    echo "Building with the hosted service as \"Octa Pass\". Set OCTAPASS_BUILD_SERVER_URL, or run this in a terminal, to pick another server." >&2
    return 0
  fi
  _pb_public="$(serve_setting OCTAPASS_PUBLIC_URL "$SERVE_PUBLIC_URL_DEFAULT")"
  _pb_public=${_pb_public%/}
  if ! is_localhost "$_pb_public"; then
    _pb_urls[_pb_n]=$_pb_public
    _pb_labels[_pb_n]="pnpm start at its public address, $_pb_public"
    _pb_n=$((_pb_n + 1))
  fi
  _pb_urls[_pb_n]=$HOSTED_SERVER_URL
  _pb_labels[_pb_n]="The hosted Octa Pass service, $HOSTED_SERVER_URL"
  _pb_n=$((_pb_n + 1))
  if [[ -n $_pb_saved && $_pb_saved != "$_pb_public" && $_pb_saved != "$HOSTED_SERVER_URL" ]]; then
    _pb_urls[_pb_n]=$_pb_saved
    _pb_labels[_pb_n]="Your current choice, $_pb_saved"
    _pb_n=$((_pb_n + 1))
  fi
  for ((_pb_i = 0; _pb_i < _pb_n; _pb_i++)); do
    if answers "${_pb_urls[_pb_i]}"; then
      _pb_labels[_pb_i]="${_pb_labels[_pb_i]} (running)"
      ((_pb_running)) || _pb_running=$((_pb_i + 1))
    else
      _pb_labels[_pb_i]="${_pb_labels[_pb_i]} (not answering now)"
    fi
    [[ ${_pb_urls[_pb_i]} != "$_pb_saved" ]] || _pb_default=$((_pb_i + 1))
  done
  ((_pb_default)) || _pb_default=$((_pb_running ? _pb_running : 1))
  PICK_BUILD_SERVER_ASKED=true
  choose _pb_pick "Which server should the apps offer as \"Octa Pass\" on their sign-in screen?" "$_pb_default" \
    "${_pb_labels[@]}" "Another address"
  if ((_pb_pick <= _pb_n)); then
    _pb_url=${_pb_urls[_pb_pick - 1]}
  else
    ask_url _pb_url "Server address, like https://vault.example.com"
  fi
  if [[ $_pb_url != https://* ]] && ! is_localhost "$_pb_url"; then
    echo "The apps only accept https:// addresses, or http://localhost on the same computer." >&2
  fi
  printf -v "$_pb_name" '%s' "$_pb_url"
}
