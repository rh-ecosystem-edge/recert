#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_jwt_rs256")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)
mkdir -p "${crypto_dir}/sa"
cp "${FIXTURES_DIR}/jwt-rs256" "${crypto_dir}/sa/token"

token_before=$(tr -d '\n' < "${crypto_dir}/sa/token")
assert_jwt_verifies "${crypto_dir}/ca.crt" "$token_before" \
    "precheck: fixture JWT should verify with original CA"
kid_before=$(jwt_header_kid "$token_before")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

token_after=$(tr -d '\n' < "${crypto_dir}/sa/token")
assert_ne "$token_after" "$token_before" "JWT should be re-signed"
kid_after=$(jwt_header_kid "$token_after")
assert_ne "$kid_after" "$kid_before" "JWT kid should change after key regeneration"
assert_jwt_verifies "${crypto_dir}/ca.crt" "$token_after" \
    "re-signed JWT should verify with regenerated CA"
assert_summary_valid "${workdir}/summary.yaml"
