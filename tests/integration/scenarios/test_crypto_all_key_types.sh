#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_all_key_types")
crypto_dir=$(setup_crypto_dir "$workdir" \
    rsa2048-ca.crt rsa2048-ca.key rsa2048-server.crt rsa2048-server.key \
    rsa4096-ca.crt rsa4096-ca.key rsa4096-server.crt rsa4096-server.key \
    ec-p256-ca.crt ec-p256-ca.key ec-p256-server.crt ec-p256-server.key \
    ec-p384-ca.crt ec-p384-ca.key ec-p384-server.crt ec-p384-server.key \
    cross-ec-under-rsa.crt cross-ec-under-rsa.key \
    cross-rsa-under-ec.crt cross-rsa-under-ec.key)

declare -A before_hashes
for f in "${crypto_dir}"/*.crt "${crypto_dir}"/*.key; do
    before_hashes["$(basename "$f")"]=$(sha256_file "$f")
done

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_cert_regenerated "RSA-2048 CA" "$crypto_dir" "rsa2048-ca.crt" "rsa2048-ca.key" \
    "${before_hashes[rsa2048-ca.crt]}" "${before_hashes[rsa2048-ca.key]}" "rsaEncryption" "2048"
assert_cert_regenerated "RSA-2048 server" "$crypto_dir" "rsa2048-server.crt" "rsa2048-server.key" \
    "${before_hashes[rsa2048-server.crt]}" "${before_hashes[rsa2048-server.key]}" "rsaEncryption" "2048"
assert_cert_regenerated "RSA-4096 CA" "$crypto_dir" "rsa4096-ca.crt" "rsa4096-ca.key" \
    "${before_hashes[rsa4096-ca.crt]}" "${before_hashes[rsa4096-ca.key]}" "rsaEncryption" "4096"
assert_cert_regenerated "RSA-4096 server" "$crypto_dir" "rsa4096-server.crt" "rsa4096-server.key" \
    "${before_hashes[rsa4096-server.crt]}" "${before_hashes[rsa4096-server.key]}" "rsaEncryption" "4096"
assert_cert_regenerated "P-256 CA" "$crypto_dir" "ec-p256-ca.crt" "ec-p256-ca.key" \
    "${before_hashes[ec-p256-ca.crt]}" "${before_hashes[ec-p256-ca.key]}" "id-ecPublicKey" "prime256v1"
assert_cert_regenerated "P-256 server" "$crypto_dir" "ec-p256-server.crt" "ec-p256-server.key" \
    "${before_hashes[ec-p256-server.crt]}" "${before_hashes[ec-p256-server.key]}" "id-ecPublicKey" "prime256v1"
assert_cert_regenerated "P-384 CA" "$crypto_dir" "ec-p384-ca.crt" "ec-p384-ca.key" \
    "${before_hashes[ec-p384-ca.crt]}" "${before_hashes[ec-p384-ca.key]}" "id-ecPublicKey" "secp384r1"
assert_cert_regenerated "P-384 server" "$crypto_dir" "ec-p384-server.crt" "ec-p384-server.key" \
    "${before_hashes[ec-p384-server.crt]}" "${before_hashes[ec-p384-server.key]}" "id-ecPublicKey" "secp384r1"

# Cross-algorithm leaves preserve their own key type, not their CA's
assert_cert_regenerated "EC leaf under RSA CA" "$crypto_dir" "cross-ec-under-rsa.crt" "cross-ec-under-rsa.key" \
    "${before_hashes[cross-ec-under-rsa.crt]}" "${before_hashes[cross-ec-under-rsa.key]}" "id-ecPublicKey" "prime256v1"
assert_cert_regenerated "RSA leaf under EC CA" "$crypto_dir" "cross-rsa-under-ec.crt" "cross-rsa-under-ec.key" \
    "${before_hashes[cross-rsa-under-ec.crt]}" "${before_hashes[cross-rsa-under-ec.key]}" "rsaEncryption" "2048"

assert_summary_valid "${workdir}/summary.yaml"
