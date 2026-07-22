#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_ecdsa_p384")
crypto_dir=$(setup_crypto_dir "$workdir" ec-p384-ca.crt ec-p384-ca.key ec-p384-server.crt ec-p384-server.key)

# Prechecks
precheck_cert "${crypto_dir}/ec-p384-ca.crt"
precheck_cert "${crypto_dir}/ec-p384-server.crt"
assert_eq "$(cert_key_algorithm "${crypto_dir}/ec-p384-ca.crt")" "id-ecPublicKey" "precheck: CA should be EC"
assert_eq "$(cert_ec_curve "${crypto_dir}/ec-p384-ca.crt")" "secp384r1" "precheck: CA should be P-384"

ca_cert_hash=$(sha256_file "${crypto_dir}/ec-p384-ca.crt")
ca_key_hash=$(sha256_file "${crypto_dir}/ec-p384-ca.key")
server_cert_hash=$(sha256_file "${crypto_dir}/ec-p384-server.crt")
server_key_hash=$(sha256_file "${crypto_dir}/ec-p384-server.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_cert_regenerated "ECDSA P-384 CA" "$crypto_dir" "ec-p384-ca.crt" "ec-p384-ca.key" \
    "$ca_cert_hash" "$ca_key_hash" "id-ecPublicKey" "secp384r1"
assert_cert_regenerated "ECDSA P-384 server" "$crypto_dir" "ec-p384-server.crt" "ec-p384-server.key" \
    "$server_cert_hash" "$server_key_hash" "id-ecPublicKey" "secp384r1"

assert_summary_valid "${workdir}/summary.yaml"
