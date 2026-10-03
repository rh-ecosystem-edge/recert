#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_ip_change_only_prunes")
crypto_dir=$(setup_crypto_dir "$workdir" \
    rsa2048-ca.crt rsa2048-ca.key rsa2048-server.crt rsa2048-server.key \
    rsa4096-ca.crt rsa4096-ca.key rsa4096-server.crt rsa4096-server.key \
    custom.key)

declare -A before_hashes
for f in rsa2048-ca.crt rsa2048-ca.key rsa2048-server.crt rsa2048-server.key \
         rsa4096-ca.crt rsa4096-ca.key rsa4096-server.crt rsa4096-server.key \
         custom.key; do
    before_hashes["$f"]=$(sha256_file "${crypto_dir}/$f")
done

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
ip_change_only: true
cn_san_replace_rules:
  - "192.168.1.100:10.0.0.50"
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "ip-change-only enabled" "should log ip-change-only pruning"

assert_ne "$(sha256_file "${crypto_dir}/rsa2048-server.crt")" "${before_hashes[rsa2048-server.crt]}" \
    "tree with old IP SAN should be regenerated"
assert_ne "$(sha256_file "${crypto_dir}/rsa2048-ca.crt")" "${before_hashes[rsa2048-ca.crt]}" \
    "CA of IP-changed tree should be regenerated"

san_after=$(cert_san_text "${crypto_dir}/rsa2048-server.crt")
assert_contains "$san_after" "10.0.0.50" "regenerated cert should have new IP SAN"
assert_not_contains "$san_after" "192.168.1.100" "regenerated cert should not keep old IP SAN"

for f in rsa4096-ca.crt rsa4096-ca.key rsa4096-server.crt rsa4096-server.key custom.key; do
    assert_file_unchanged "${crypto_dir}/$f" "${before_hashes[$f]}" \
        "unrelated $f should not be rewritten in ip-change-only mode"
done

assert_summary_valid "${workdir}/summary.yaml"
