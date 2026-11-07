#!/bin/sh
# Writes raivo-aes256.zip and raivo-aes128.zip from raivo.json with 7-Zip (independent of the
# Rust importer): raivo-otp-export.json and an HTML page, the two files Raivo's
# DataExportFeature.swift puts in its export, password `correct horse battery staple`.
#
#   raivo-aes256.zip  like Raivo: WinZip AES-256, stored (SSZipArchive, compressionLevel 0, aes: true)
#   raivo-aes128.zip  WinZip AES-128 and deflate, which Raivo doesn't write, for the other paths
#
# 7-Zip isn't needed to run the tests. Get it from https://www.7-zip.org (the macOS build is one
# binary, `7zz`), then:
#
#   SEVENZIP=/path/to/7zz sh crates/octapass-core/tests/import-fixtures/make-raivo.sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$here/raivo.json" "$work/raivo-otp-export.json"
printf '<html><body><h1>Raivo OTP export</h1><p>Synthetic test data.</p></body></html>\n' > "$work/raivo-otp-export.html"
# A fixed date, so the archives only change when their content does.
touch -t 202510230000 "$work"/raivo-otp-export.*
rm -f "$here/raivo-aes256.zip" "$here/raivo-aes128.zip"
cd "$work"
"$SEVENZIP" a -tzip -mem=AES256 -mx0 -p'correct horse battery staple' "$here/raivo-aes256.zip" raivo-otp-export.html raivo-otp-export.json >/dev/null
"$SEVENZIP" a -tzip -mem=AES128 -mx5 -p'correct horse battery staple' "$here/raivo-aes128.zip" raivo-otp-export.html raivo-otp-export.json >/dev/null
