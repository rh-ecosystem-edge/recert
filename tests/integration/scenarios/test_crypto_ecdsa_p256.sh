#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_ecdsa_p256")
crypto_dir=$(setup_crypto_dir "$workdir" ec-p256-ca.crt ec-p256-ca.key ec-p256-server.crt ec-p256-server.key)

ca_cert_hash=$(sha256_file "${crypto_dir}/ec-p256-ca.crt")
ca_key_hash=$(sha256_file "${crypto_dir}/ec-p256-ca.key")
server_cert_hash=$(sha256_file "${crypto_dir}/ec-p256-server.crt")
server_key_hash=$(sha256_file "${crypto_dir}/ec-p256-server.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_cert_regenerated "ECDSA P-256 CA" "$crypto_dir" "ec-p256-ca.crt" "ec-p256-ca.key" \
    "$ca_cert_hash" "$ca_key_hash" "id-ecPublicKey" "prime256v1"
assert_cert_regenerated "ECDSA P-256 server" "$crypto_dir" "ec-p256-server.crt" "ec-p256-server.key" \
    "$server_cert_hash" "$server_key_hash" "id-ecPublicKey" "prime256v1"

assert_summary_valid "${workdir}/summary.yaml"
