#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_use_cert")
# Only place the cert (no key) in the crypto dir — use_cert_rules replaces
# the cert wholesale and does not regenerate the associated key.
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt)

cp "${FIXTURES_DIR}/replacement.crt" "${workdir}/replacement.crt"

replacement_serial=$(openssl x509 -noout -serial -in "${workdir}/replacement.crt" 2>/dev/null)

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
use_cert_rules:
  - ${workdir}/replacement.crt
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

# After recert, the CA should be the replacement cert
ca_serial=$(openssl x509 -noout -serial -in "${crypto_dir}/ca.crt" 2>/dev/null)
assert_eq "$ca_serial" "$replacement_serial" \
    "CA cert should be the replacement cert after recert"

assert_summary_valid "${workdir}/summary.yaml"
