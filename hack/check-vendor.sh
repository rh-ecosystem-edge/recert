#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$PROJECT_DIR"

# The source replacement in .cargo/config.toml makes this check independent of
# network availability and fails when Cargo.lock references a crate absent from
# the committed vendor tree.
cargo metadata --locked --offline --format-version 1 >/dev/null

# The committed vendor tree is intentionally filtered to Linux targets. The
# metadata check above is platform-independent; the offline compilation check
# belongs in the Linux CI jobs and is skipped on developer workstations such as
# macOS, where the filtered Linux vendor tree cannot satisfy host-specific cfgs.
if [[ "$(uname -s)" == "Linux" ]]; then
    cargo check --locked --offline --all-targets
else
    echo "Skipping offline compilation check on non-Linux host"
fi
