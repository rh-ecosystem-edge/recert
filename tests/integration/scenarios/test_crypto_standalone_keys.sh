#!/usr/bin/env bash

set -euo pipefail

# Standalone .key / .pub regeneration (previously e2e-only via e2e_test.sh).
# Covers RSA PUBLIC KEY (PKCS#1) and SPKI PUBLIC KEY formats.

workdir=$(setup_test_workdir "crypto_standalone_keys")
crypto_dir="${workdir}/crypto"
mkdir -p "$crypto_dir"

cp "${FIXTURES_DIR}/standalone-rsa.key" "${crypto_dir}/standalone-rsa.key"
cp "${FIXTURES_DIR}/standalone-rsa.pub" "${crypto_dir}/standalone-rsa.pub"
cp "${FIXTURES_DIR}/standalone-ec.key" "${crypto_dir}/standalone-ec.key"
cp "${FIXTURES_DIR}/standalone-ec.pub" "${crypto_dir}/standalone-ec.pub"
cp "${FIXTURES_DIR}/standalone-ed25519.key" "${crypto_dir}/standalone-ed25519.key"
cp "${FIXTURES_DIR}/standalone-ed25519.pub" "${crypto_dir}/standalone-ed25519.pub"

declare -A before_hashes
for f in standalone-rsa.key standalone-rsa.pub \
         standalone-ec.key standalone-ec.pub \
         standalone-ed25519.key standalone-ed25519.pub; do
    before_hashes["$f"]=$(sha256_file "${crypto_dir}/$f")
done

assert_pem_tag "${crypto_dir}/standalone-rsa.pub" "RSA PUBLIC KEY" \
    "fixture standalone RSA pub should be PKCS#1 RSA PUBLIC KEY"
assert_pem_tag "${crypto_dir}/standalone-ec.pub" "PUBLIC KEY" \
    "fixture standalone EC pub should be SPKI PUBLIC KEY"
assert_pem_tag "${crypto_dir}/standalone-ed25519.pub" "PUBLIC KEY" \
    "fixture standalone Ed25519 pub should be SPKI PUBLIC KEY"

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

for f in standalone-rsa.key standalone-rsa.pub \
         standalone-ec.key standalone-ec.pub \
         standalone-ed25519.key standalone-ed25519.pub; do
    assert_ne "$(sha256_file "${crypto_dir}/$f")" "${before_hashes[$f]}" \
        "$f should have been regenerated"
done

assert_pem_tag "${crypto_dir}/standalone-rsa.pub" "RSA PUBLIC KEY" \
    "regenerated standalone RSA pub should stay PKCS#1 RSA PUBLIC KEY"
assert_pem_tag "${crypto_dir}/standalone-ec.pub" "PUBLIC KEY" \
    "regenerated standalone EC pub should stay SPKI PUBLIC KEY"
assert_pem_tag "${crypto_dir}/standalone-ed25519.pub" "PUBLIC KEY" \
    "regenerated standalone Ed25519 pub should stay SPKI PUBLIC KEY"

# Keys must still parse
precheck_key "${crypto_dir}/standalone-rsa.key" "regenerated RSA standalone key"
precheck_key "${crypto_dir}/standalone-ec.key" "regenerated EC standalone key"
precheck_key "${crypto_dir}/standalone-ed25519.key" "regenerated Ed25519 standalone key"

assert_summary_valid "${workdir}/summary.yaml"
