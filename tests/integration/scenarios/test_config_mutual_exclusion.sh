#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "config_mutual_exclusion")

cases=(
    "extend_expiration:force_expire:extend_expiration and force_expire are mutually exclusive"
    "dry_run:force_expire:dry_run and force_expire are mutually exclusive"
    "dry_run:extend_expiration:dry_run and extend_expiration are mutually exclusive"
    "dry_run:etcd_defrag:dry_run and etcd_defrag are mutually exclusive"
)

for case in "${cases[@]}"; do
    IFS=: read -r key1 key2 expected_msg <<< "$case"
    cat > "${workdir}/config.yaml" <<EOF
${key1}: true
${key2}: true
EOF
    output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
    assert_contains "$output" "$expected_msg" "${key1} + ${key2} should be rejected"
done
