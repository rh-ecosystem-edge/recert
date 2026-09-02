#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "config_unknown_key")

cat > "${workdir}/config.yaml" <<'EOF'
dry_run: true
bogus_field: true
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "unknown keys" "should reject unknown config keys"
