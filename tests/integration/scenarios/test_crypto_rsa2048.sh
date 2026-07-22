#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_rsa2048")
crypto_dir=$(setup_crypto_dir "$workdir" rsa2048-ca.crt rsa2048-ca.key rsa2048-server.crt rsa2048-server.key)

ca_cert_hash=$(sha256_file "${crypto_dir}/rsa2048-ca.crt")
ca_key_hash=$(sha256_file "${crypto_dir}/rsa2048-ca.key")
server_cert_hash=$(sha256_file "${crypto_dir}/rsa2048-server.crt")
server_key_hash=$(sha256_file "${crypto_dir}/rsa2048-server.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_cert_regenerated "RSA-2048 CA" "$crypto_dir" "rsa2048-ca.crt" "rsa2048-ca.key" \
    "$ca_cert_hash" "$ca_key_hash" "rsaEncryption" "2048"
assert_cert_regenerated "RSA-2048 server" "$crypto_dir" "rsa2048-server.crt" "rsa2048-server.key" \
    "$server_cert_hash" "$server_key_hash" "rsaEncryption" "2048"

assert_summary_valid "${workdir}/summary.yaml"
