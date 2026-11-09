#!/bin/sh
# Installs the Octa Pass command-line tool: `octapass` and its helpers (git-credential-octapass,
# octapass-git-sign, docker-credential-octapass), for macOS and Linux.
#
#   curl -fsSL __OCTAPASS_SITE__/install.sh | sh
#
# It downloads the release archive for this computer from GitHub, checks it against the release's
# SHA256SUMS and copies the programs to ~/.local/bin (or OCTAPASS_INSTALL_DIR). Nothing runs as
# root, nothing else is changed, and nothing is sent anywhere but the download. When there's no
# release build for this computer yet and Rust is installed, it builds the CLI from source with
# `cargo install` instead.
#
#   OCTAPASS_VERSION=v1.2.3        a release tag instead of the latest release
#   OCTAPASS_INSTALL_DIR=/usr/local/bin   where to put the programs
set -eu

REPO="${OCTAPASS_REPO:-__OCTAPASS_REPO__}"
VERSION="${OCTAPASS_VERSION:-latest}"
INSTALL_DIR="${OCTAPASS_INSTALL_DIR:-$HOME/.local/bin}"
PROGRAMS="octapass git-credential-octapass octapass-git-sign docker-credential-octapass"

say() { printf '%s\n' "$*" >&2; }
fail() { say "open pass: $*"; exit 1; }

target() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64) arch=aarch64 ;;
    *) fail "there's no build for this processor ($arch)." ;;
  esac
  case "$os" in
    Darwin)
      # A shell under Rosetta reports x86_64 on an Apple silicon Mac: use the native build.
      if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
        arch=aarch64
      fi
      echo "$arch-apple-darwin" ;;
    Linux) echo "$arch-unknown-linux-gnu" ;;
    *) fail "this script is for macOS and Linux. On Windows, see __OCTAPASS_SITE__/docs/platforms/cli/#install" ;;
  esac
}

fetch() { # url, file
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$2" "$1"
  else
    fail "curl or wget is needed to download the CLI."
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    fail "sha256sum or shasum is needed to check the download."
  fi
}

from_source() {
  if ! command -v cargo >/dev/null 2>&1; then
    fail "there's no release build for $1 yet. Install Rust (https://rustup.rs) and run this again to build it from source."
  fi
  say "There's no release build for $1 yet, so the CLI is built from source with cargo. This takes a few minutes."
  cargo install --locked --git "https://github.com/$REPO" octapass-cli
  say ""
  say "Installed with cargo into ~/.cargo/bin."
  next_steps
  exit 0
}

next_steps() {
  say ""
  say "Next: if the Octa Pass app is on this computer, any octapass command uses its account,"
  say "unlocked whenever the app is. Otherwise run: octapass login"
}

main() {
  target=$(target)
  archive="octapass-cli-$target.tar.gz"
  if [ "$VERSION" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$VERSION"
  fi

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT INT TERM

  say "Downloading the Octa Pass CLI for $target…"
  if ! fetch "$base/$archive" "$work/$archive" 2>/dev/null; then
    from_source "$target"
  fi
  fetch "$base/SHA256SUMS" "$work/SHA256SUMS" || fail "the release has no SHA256SUMS to check the download against."
  expected=$(grep " $archive\$" "$work/SHA256SUMS" | cut -d' ' -f1)
  [ -n "$expected" ] || fail "SHA256SUMS doesn't list $archive."
  [ "$(sha256 "$work/$archive")" = "$expected" ] || fail "the download doesn't match SHA256SUMS. Nothing was installed."

  tar -xzf "$work/$archive" -C "$work"
  mkdir -p "$INSTALL_DIR"
  for program in $PROGRAMS; do
    [ -f "$work/$program" ] || continue
    install -m 0755 "$work/$program" "$INSTALL_DIR/$program"
  done
  say "Installed $("$INSTALL_DIR/octapass" --version 2>/dev/null || echo octapass) in $INSTALL_DIR."

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      say ""
      say "$INSTALL_DIR isn't on your PATH yet. Add this to your shell's startup file:"
      say "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
  esac
  next_steps
}

main "$@"
