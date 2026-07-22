#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_rsa4096")
crypto_dir=$(setup_crypto_dir "$workdir" rsa4096-ca.crt rsa4096-ca.key rsa4096-server.crt rsa4096-server.key)

ca_cert_hash=$(sha256_file "${crypto_dir}/rsa4096-ca.crt")
ca_key_hash=$(sha256_file "${crypto_dir}/rsa4096-ca.key")
server_cert_hash=$(sha256_file "${crypto_dir}/rsa4096-server.crt")
server_key_hash=$(sha256_file "${crypto_dir}/rsa4096-server.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_cert_regenerated "RSA-4096 CA" "$crypto_dir" "rsa4096-ca.crt" "rsa4096-ca.key" \
    "$ca_cert_hash" "$ca_key_hash" "rsaEncryption" "4096"
assert_cert_regenerated "RSA-4096 server" "$crypto_dir" "rsa4096-server.crt" "rsa4096-server.key" \
    "$server_cert_hash" "$server_key_hash" "rsaEncryption" "4096"

assert_summary_valid "${workdir}/summary.yaml"
