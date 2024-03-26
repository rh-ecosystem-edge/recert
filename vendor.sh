#!/bin/bash

set -euxo pipefail

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR"

# Make sure user installed cargo-vendor-filterer
if ! command -v cargo-vendor-filterer &>/dev/null; then
	echo "cargo-vendor-filterer could not be found, please install it with 'cargo install cargo-vendor-filterer'"
	exit 1
fi

rm -rf vendor
sudo unshare --mount -- bash -c "mount --bind /dev/null .cargo/config.toml && sudo -u $USER env PATH=$PATH \
    cargo vendor-filterer \
"
