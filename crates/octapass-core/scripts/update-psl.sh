#!/bin/sh
# Refreshes data/public_suffix_list.dat from publicsuffix.org. Run the core tests afterwards.
set -eu
cd "$(dirname "$0")/.."
curl -fsSL https://publicsuffix.org/list/public_suffix_list.dat -o data/public_suffix_list.dat
echo "Updated data/public_suffix_list.dat ($(grep -cv '^//' data/public_suffix_list.dat) lines)"
