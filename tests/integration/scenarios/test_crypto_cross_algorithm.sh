#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_cross_algorithm")
crypto_dir=$(setup_crypto_dir "$workdir" \
    rsa2048-ca.crt rsa2048-ca.key \
    ec-p256-ca.crt ec-p256-ca.key \
    cross-ec-under-rsa.crt cross-ec-under-rsa.key \
    cross-rsa-under-ec.crt cross-rsa-under-ec.key)

ec_under_rsa_cert_hash=$(sha256_file "${crypto_dir}/cross-ec-under-rsa.crt")
ec_under_rsa_key_hash=$(sha256_file "${crypto_dir}/cross-ec-under-rsa.key")
rsa_under_ec_cert_hash=$(sha256_file "${crypto_dir}/cross-rsa-under-ec.crt")
rsa_under_ec_key_hash=$(sha256_file "${crypto_dir}/cross-rsa-under-ec.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_cert_regenerated "EC leaf under RSA CA" "$crypto_dir" \
    "cross-ec-under-rsa.crt" "cross-ec-under-rsa.key" \
    "$ec_under_rsa_cert_hash" "$ec_under_rsa_key_hash" "id-ecPublicKey" "prime256v1"

assert_cert_regenerated "RSA leaf under EC CA" "$crypto_dir" \
    "cross-rsa-under-ec.crt" "cross-rsa-under-ec.key" \
    "$rsa_under_ec_cert_hash" "$rsa_under_ec_key_hash" "rsaEncryption" "2048"

assert_summary_valid "${workdir}/summary.yaml"
