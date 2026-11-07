# Shared by the scripts that use the iPhone and Android libraries built from Rust. Source it,
# don't run it. Written for the bash 3.2 that ships with macOS.

STALE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# rebuild_if_stale CRATE OUTPUT SCRIPT [EXTRA FILE…]
# Runs SCRIPT when OUTPUT is missing, or was built from other sources than CRATE has now: the
# crate, the local crates it compiles, the Cargo files, SCRIPT and the EXTRA files
# (scripts/lib/sources-hash.mjs). The committed Swift and Kotlin bindings change with the Rust API,
# so a library from older sources no longer compiles against them. The hash goes in
# target/sources-hash/ once SCRIPT has succeeded.
rebuild_if_stale() {
  local crate=$1 output=$2 script=$3 stamp hash recorded=""
  shift 3
  stamp="$STALE_ROOT/target/sources-hash/$crate-$(basename "$output").txt"
  hash="$(node "$STALE_ROOT/scripts/lib/sources-hash.mjs" "$crate" "$script" ${@+"$@"})"
  [[ ! -f "$stamp" ]] || recorded="$(cat "$stamp")"
  if [[ -e "$output" && "$recorded" == "$hash" ]]; then
    return 0
  fi
  if [[ ! -e "$output" ]]; then
    echo "Building $(basename "$output") from the Rust sources." >&2
  elif [[ -n "$recorded" ]]; then
    echo "Rebuilding $(basename "$output"): the Rust sources changed since it was built." >&2
  else
    echo "Rebuilding $(basename "$output"): it has no record of the sources it was built from." >&2
  fi
  "$script"
  mkdir -p "$(dirname "$stamp")"
  printf '%s\n' "$hash" >"$stamp"
}
