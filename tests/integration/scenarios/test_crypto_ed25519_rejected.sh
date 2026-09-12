#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_ed25519_rejected")
crypto_dir="${workdir}/crypto"
mkdir -p "$crypto_dir"

openssl genpkey -algorithm Ed25519 -out "${crypto_dir}/ed25519-ca.key" 2>/dev/null
openssl req -x509 -key "${crypto_dir}/ed25519-ca.key" -out "${crypto_dir}/ed25519-ca.crt" \
    -days 365 -subj "/CN=ed25519-test-ca" 2>/dev/null

ca_cert_hash=$(sha256_file "${crypto_dir}/ed25519-ca.crt")
ca_key_hash=$(sha256_file "${crypto_dir}/ed25519-ca.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_ne "$(sha256_file "${crypto_dir}/ed25519-ca.crt")" "$ca_cert_hash" \
    "Ed25519 cert should have been regenerated"
assert_ne "$(sha256_file "${crypto_dir}/ed25519-ca.key")" "$ca_key_hash" \
    "Ed25519 key should have been regenerated"

# Verify the regenerated cert is valid
openssl x509 -noout -in "${crypto_dir}/ed25519-ca.crt" 2>/dev/null \
    || { echo "FAIL: regenerated Ed25519 cert is not valid X.509" >&2; return 1; }

assert_summary_valid "${workdir}/summary.yaml"
