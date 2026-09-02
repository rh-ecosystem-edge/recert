#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_ec_pkcs8_input")
crypto_dir="${workdir}/crypto"
mkdir -p "$crypto_dir"

cp "${FIXTURES_DIR}/ec-p256-ca.crt" "${crypto_dir}/ec-p256-ca.crt"
cp "${FIXTURES_DIR}/ec-p256-ca-pkcs8.key" "${crypto_dir}/ec-p256-ca.key"
cp "${FIXTURES_DIR}/ec-p256-server.crt" "${crypto_dir}/ec-p256-server.crt"
cp "${FIXTURES_DIR}/ec-p256-server-pkcs8.key" "${crypto_dir}/ec-p256-server.key"

assert_pem_tag "${crypto_dir}/ec-p256-ca.key" "PRIVATE KEY" "fixture CA key should be PKCS#8"
assert_pem_tag "${crypto_dir}/ec-p256-server.key" "PRIVATE KEY" "fixture server key should be PKCS#8"

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

assert_cert_regenerated "PKCS#8 P-256 CA" "$crypto_dir" "ec-p256-ca.crt" "ec-p256-ca.key" \
    "$ca_cert_hash" "$ca_key_hash" "id-ecPublicKey" "prime256v1"
assert_cert_regenerated "PKCS#8 P-256 server" "$crypto_dir" "ec-p256-server.crt" "ec-p256-server.key" \
    "$server_cert_hash" "$server_key_hash" "id-ecPublicKey" "prime256v1"
assert_chain_valid "${crypto_dir}/ec-p256-ca.crt" "${crypto_dir}/ec-p256-server.crt"
assert_summary_valid "${workdir}/summary.yaml"
