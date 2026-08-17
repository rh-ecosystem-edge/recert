#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_cn_san_ipv6")
crypto_dir=$(setup_crypto_dir "$workdir" \
    rsa2048-ca.crt rsa2048-ca.key ipv6-server.crt ipv6-server.key)

san_before=$(cert_san_text "${crypto_dir}/ipv6-server.crt")
# OpenSSL prints IPv6 SANs in expanded form
assert_contains "$san_before" "2001:DB8:0:0:0:0:0:1" "original cert should have old IPv6 SAN"

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
cn_san_replace_rules:
  - "2001:db8::1,2001:db8::50"
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

san_after=$(cert_san_text "${crypto_dir}/ipv6-server.crt")
assert_contains "$san_after" "2001:DB8:0:0:0:0:0:50" "regenerated cert should have new IPv6 SAN"
assert_not_contains "$san_after" "2001:DB8:0:0:0:0:0:1" "regenerated cert should NOT have old IPv6 SAN"
assert_chain_valid "${crypto_dir}/rsa2048-ca.crt" "${crypto_dir}/ipv6-server.crt"
assert_summary_valid "${workdir}/summary.yaml"
