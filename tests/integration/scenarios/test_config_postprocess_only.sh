#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "config_postprocess_only")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)

ca_hash_before=$(sha256_file "${crypto_dir}/ca.crt")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
postprocess_only: true
summary_file: ${workdir}/summary.yaml
EOF

# postprocess_only skips crypto scanning/regeneration entirely,
# so the cert should remain untouched
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_eq "$(sha256_file "${crypto_dir}/ca.crt")" "$ca_hash_before" \
    "postprocess_only should NOT regenerate certs"
