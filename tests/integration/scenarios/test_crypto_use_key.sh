#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_use_key")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)

# Copy custom key outside the scanned crypto dir
cp "${FIXTURES_DIR}/custom.key" "${workdir}/custom.key"

custom_key_modulus=$(openssl rsa -noout -modulus -in "${workdir}/custom.key" 2>/dev/null)

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
use_key_rules:
  - "rsa2048-root-ca:${workdir}/custom.key"
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

# After recert, the CA cert should be signed with our custom key
ca_modulus=$(openssl x509 -noout -modulus -in "${crypto_dir}/ca.crt" 2>/dev/null)
assert_eq "$ca_modulus" "$custom_key_modulus" \
    "CA cert should use the custom key after recert"

assert_summary_valid "${workdir}/summary.yaml"
