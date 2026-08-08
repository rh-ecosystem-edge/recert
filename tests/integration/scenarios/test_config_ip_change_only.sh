#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "config_ip_change_only")

cat > "${workdir}/config.yaml" <<'EOF'
ip_change_only: true
dry_run: true
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "ip-change-only requires at least one cn_san_replace rule" \
    "ip_change_only without cn_san_replace_rules should be rejected"
