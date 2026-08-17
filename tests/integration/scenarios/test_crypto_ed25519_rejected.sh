#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_ed25519_rejected")
crypto_dir="${workdir}/crypto"
mkdir -p "$crypto_dir"

openssl genpkey -algorithm Ed25519 -out "${crypto_dir}/ed25519-ca.key" 2>/dev/null
openssl req -x509 -key "${crypto_dir}/ed25519-ca.key" -out "${crypto_dir}/ed25519-ca.crt" \
    -days 365 -subj "/CN=ed25519-test-ca" 2>/dev/null

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

# Ed25519 is not yet supported — recert ignores the certs and fails
# because no processable crypto objects are found.
# (positive Ed25519 test to be added after PR #1817 merges)
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "Unexpected count of crypto objects found" \
    "should fail because Ed25519 certs are not processable"
