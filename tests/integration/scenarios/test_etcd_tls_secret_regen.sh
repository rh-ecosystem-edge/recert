#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_tls_secret_regen")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

setup_webhook_authenticator "$crypto_dir"

etcd_put_tls_secret "default" "app-tls" \
    "${crypto_dir}/server.crt" "${crypto_dir}/server.key"

precheck_etcd_key "/kubernetes.io/secrets/default/app-tls" "TLS secret seeded"
orig_cert_hash=$(sha256_file "${crypto_dir}/server.crt")
orig_key_hash=$(sha256_file "${crypto_dir}/server.key")

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
crypto_dirs:
  - ${crypto_dir}
cluster_customization_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "Regenerated all crypto objects" "should regenerate crypto"
assert_contains "$output" "Committing to actual etcd" "should persist etcd cache"

etcd_secret_pems "/kubernetes.io/secrets/default/app-tls" \
    "${workdir}/from-etcd.crt" "${workdir}/from-etcd.key"
precheck_cert "${workdir}/from-etcd.crt" "etcd tls.crt should still be a cert"
precheck_key "${workdir}/from-etcd.key" "etcd tls.key should still be a key"
assert_ne "$(sha256_file "${workdir}/from-etcd.crt")" "$orig_cert_hash" \
    "etcd tls.crt should be regenerated"
assert_ne "$(sha256_file "${workdir}/from-etcd.key")" "$orig_key_hash" \
    "etcd tls.key should be regenerated"
assert_chain_valid "${crypto_dir}/ca.crt" "${workdir}/from-etcd.crt" \
    "regenerated etcd leaf should verify against regenerated CA"
assert_summary_valid "${workdir}/summary.yaml"
