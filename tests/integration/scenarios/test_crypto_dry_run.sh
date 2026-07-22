#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_dry_run")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

ca_hash_before=$(sha256_file "${crypto_dir}/ca.crt")
server_hash_before=$(sha256_file "${crypto_dir}/server.crt")
ca_key_hash_before=$(sha256_file "${crypto_dir}/ca.key")
server_key_hash_before=$(sha256_file "${crypto_dir}/server.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
dry_run: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_eq "$(sha256_file "${crypto_dir}/ca.crt")" "$ca_hash_before" "CA cert should NOT change in dry-run"
assert_eq "$(sha256_file "${crypto_dir}/server.crt")" "$server_hash_before" "server cert should NOT change in dry-run"
assert_eq "$(sha256_file "${crypto_dir}/ca.key")" "$ca_key_hash_before" "CA key should NOT change in dry-run"
assert_eq "$(sha256_file "${crypto_dir}/server.key")" "$server_key_hash_before" "server key should NOT change in dry-run"
