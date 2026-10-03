#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "config_cli_vs_env")

cat > "${workdir}/config.yaml" <<'EOF'
dry_run: true
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure --dry-run)
assert_contains "$output" "RECERT_CONFIG is set" \
    "RECERT_CONFIG + CLI args should be rejected"
