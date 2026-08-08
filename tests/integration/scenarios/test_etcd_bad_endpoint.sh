#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_bad_endpoint")

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:9999
force_expire: true
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "Connection refused" "should report etcd connection failure"
