#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VENDOR_FILTERER=${VENDOR_FILTERER:-cargo-vendor-filterer}
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/recert-vendor.XXXXXX")

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

if ! command -v "$VENDOR_FILTERER" >/dev/null 2>&1; then
    echo "${VENDOR_FILTERER} is required; install cargo-vendor-filterer first" >&2
    exit 1
fi

cd "$PROJECT_DIR"

# cargo-vendor-filterer ignores the repository's vendored-source replacement
# while fetching crates. This lets the command refresh vendor/ after
# Cargo.toml or Cargo.lock changes without requiring a privileged mount or a
# modified Cargo config.
"$VENDOR_FILTERER" --locked "$TEMP_DIR/vendor"

rm -rf "$PROJECT_DIR/vendor"
mv "$TEMP_DIR/vendor" "$PROJECT_DIR/vendor"

echo "Updated vendored dependencies in $PROJECT_DIR/vendor"
