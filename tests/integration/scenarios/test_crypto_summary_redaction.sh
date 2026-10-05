#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_summary_redaction")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
summary_file_clean: ${workdir}/summary_redacted.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_summary_valid "${workdir}/summary.yaml"
assert_summary_valid "${workdir}/summary_redacted.yaml"

redacted_content=$(cat "${workdir}/summary_redacted.yaml")
assert_not_contains "$redacted_content" "BEGIN RSA PRIVATE KEY" \
    "redacted summary should not contain private key PEM markers"
assert_not_contains "$redacted_content" "BEGIN PRIVATE KEY" \
    "redacted summary should not contain generic private key PEM markers"

key_body_line=$(sed -n '2p' "${crypto_dir}/ca.key")
assert_not_contains "$redacted_content" "$key_body_line" \
    "redacted summary should not contain private key body content"
