#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_scan_dir")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

ca_hash_before=$(sha256_file "${crypto_dir}/ca.crt")
server_hash_before=$(sha256_file "${crypto_dir}/server.crt")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
summary_file: ${workdir}/summary.yaml
force_expire: true
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

ca_hash_after=$(sha256_file "${crypto_dir}/ca.crt")
server_hash_after=$(sha256_file "${crypto_dir}/server.crt")

assert_ne "$ca_hash_after" "$ca_hash_before" "CA cert should have been regenerated"
assert_ne "$server_hash_after" "$server_hash_before" "server cert should have been regenerated"

assert_summary_valid "${workdir}/summary.yaml"
