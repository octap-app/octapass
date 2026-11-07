#!/usr/bin/env bash
# Cross-compiles the Windows x64 installer (NSIS) on macOS, without Visual Studio or a full LLVM:
# cargo-xwin fetches the MSVC CRT and Windows SDK, Apple's clang compiles the C parts for the
# windows-msvc target, Rust's llvm-tools stand in for llvm-lib, and mingw-w64's windres (installed
# with NSIS) compiles the resources. The installer is unsigned, and like every Windows build so
# far it doesn't ship octapass-native-host.exe, so only the frontend is built beforehand. The
# GitHub Actions release workflow builds the same installer on Windows.
#
#   brew install nsis && cargo install cargo-xwin --locked && rustup component add llvm-tools
#   rustup target add x86_64-pc-windows-msvc
#   VITE_SERVER_URL=https://vault.example.com apps/desktop/scripts/build-windows.sh
#
# → apps/desktop/target/x86_64-pc-windows-msvc/release/bundle/nsis/Octa Pass_<version>_x64-setup.exe
set -euo pipefail
desktop="$(cd "$(dirname "$0")/.." && pwd)"

tools="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
if [[ ! -x "$tools/llvm-ar" ]]; then
  echo "Needs llvm-ar from Rust's llvm-tools: rustup component add llvm-tools" >&2
  exit 1
fi
# llvm-ar works as llvm-lib when it's called by that name.
shims="$(mktemp -d)"
trap 'rm -rf "$shims"' EXIT
ln -s "$tools/llvm-ar" "$shims/llvm-lib"

cd "$desktop"
PATH="$shims:$PATH" \
XWIN_CROSS_COMPILER=clang \
RC_x86_64_pc_windows_msvc="${RC_x86_64_pc_windows_msvc:-x86_64-w64-mingw32-windres}" \
  cargo tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc --bundles nsis \
  --config '{"build":{"beforeBuildCommand":"pnpm build"}}'
