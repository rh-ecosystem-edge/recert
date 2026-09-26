#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_extend_expiration")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

not_after_before=$(openssl x509 -noout -enddate -in "${crypto_dir}/ca.crt" 2>/dev/null | cut -d= -f2)
epoch_before=$(date -d "$not_after_before" +%s)

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
extend_expiration: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

not_after_after=$(openssl x509 -noout -enddate -in "${crypto_dir}/ca.crt" 2>/dev/null | cut -d= -f2)
epoch_after=$(date -d "$not_after_after" +%s)

assert_lt "$epoch_before" "$epoch_after" \
    "extend_expiration should push notAfter further into the future"

assert_summary_valid "${workdir}/summary.yaml"
