#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_chain_validation")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

# Precheck: leaf cert verifies against CA before regeneration
openssl verify -CAfile "${crypto_dir}/ca.crt" "${crypto_dir}/server.crt" > /dev/null 2>&1 \
    || { echo "PRECHECK FAIL: leaf should verify against CA before recert"; exit 1; }

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

openssl verify -no_check_time -CAfile "${crypto_dir}/ca.crt" "${crypto_dir}/server.crt" > /dev/null 2>&1 \
    || { echo "FAIL: regenerated leaf cert should verify against regenerated CA"; exit 1; }

assert_summary_valid "${workdir}/summary.yaml"
