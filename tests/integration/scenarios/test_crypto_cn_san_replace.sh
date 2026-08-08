#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_cn_san_replace")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

# Prechecks
precheck_cert "${crypto_dir}/server.crt"
precheck_cert "${crypto_dir}/ca.crt"
san_before=$(openssl x509 -noout -text -in "${crypto_dir}/server.crt" 2>/dev/null | grep -A2 "Subject Alternative Name")
assert_contains "$san_before" "api.old-cluster.example.com" "original cert should have old DNS SAN"
assert_contains "$san_before" "192.168.1.100" "original cert should have old IP SAN"

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
cn_san_replace_rules:
  - "api.old-cluster.example.com:api.new-cluster.example.com"
  - "192.168.1.100:10.0.0.50"
summary_file: ${workdir}/summary.yaml
force_expire: true
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

san_after=$(openssl x509 -noout -text -in "${crypto_dir}/server.crt" 2>/dev/null | grep -A2 "Subject Alternative Name")
assert_contains "$san_after" "api.new-cluster.example.com" "regenerated cert should have new DNS SAN"
assert_not_contains "$san_after" "api.old-cluster.example.com" "regenerated cert should NOT have old DNS SAN"
assert_contains "$san_after" "10.0.0.50" "regenerated cert should have new IP SAN"
assert_not_contains "$san_after" "192.168.1.100" "regenerated cert should NOT have old IP SAN"
