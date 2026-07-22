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

# Verify every cert and key was regenerated
for f in "${crypto_dir}"/*.crt "${crypto_dir}"/*.key; do
    name=$(basename "$f")
    assert_ne "$(sha256_file "$f")" "${before_hashes[$name]}" \
        "${name} should have been regenerated"
done

# Verify key algorithms are preserved
assert_eq "$(cert_key_algorithm "${crypto_dir}/rsa2048-ca.crt")" "rsaEncryption" "RSA-2048 CA algo"
assert_eq "$(cert_key_size "${crypto_dir}/rsa2048-ca.crt")" "2048" "RSA-2048 CA size"
assert_eq "$(cert_key_algorithm "${crypto_dir}/rsa4096-ca.crt")" "rsaEncryption" "RSA-4096 CA algo"
assert_eq "$(cert_key_size "${crypto_dir}/rsa4096-ca.crt")" "4096" "RSA-4096 CA size"
assert_eq "$(cert_key_algorithm "${crypto_dir}/ec-p256-ca.crt")" "id-ecPublicKey" "P-256 CA algo"
assert_eq "$(cert_ec_curve "${crypto_dir}/ec-p256-ca.crt")" "prime256v1" "P-256 CA curve"
assert_eq "$(cert_key_algorithm "${crypto_dir}/ec-p384-ca.crt")" "id-ecPublicKey" "P-384 CA algo"
assert_eq "$(cert_ec_curve "${crypto_dir}/ec-p384-ca.crt")" "secp384r1" "P-384 CA curve"

# Cross-algorithm leaves preserve their own key type, not their CA's
assert_eq "$(cert_key_algorithm "${crypto_dir}/cross-ec-under-rsa.crt")" "id-ecPublicKey" \
    "EC leaf under RSA CA should stay EC"
assert_eq "$(cert_key_algorithm "${crypto_dir}/cross-rsa-under-ec.crt")" "rsaEncryption" \
    "RSA leaf under EC CA should stay RSA"

assert_summary_valid "${workdir}/summary.yaml"
