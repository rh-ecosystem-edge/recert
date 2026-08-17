#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_kubeconfig_embedded")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

write_kubeconfig "${crypto_dir}/admin.kubeconfig" \
    "${crypto_dir}/server.crt" "${crypto_dir}/server.key" "${crypto_dir}/ca.crt"

kube_hash_before=$(sha256_file "${crypto_dir}/admin.kubeconfig")
cert_hash_before=$(sha256_file "${crypto_dir}/server.crt")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_ne "$(sha256_file "${crypto_dir}/admin.kubeconfig")" "$kube_hash_before" \
    "kubeconfig should be rewritten"
assert_ne "$(sha256_file "${crypto_dir}/server.crt")" "$cert_hash_before" \
    "standalone cert should be regenerated"

kubeconfig_extract_client_pem "${crypto_dir}/admin.kubeconfig" \
    "${workdir}/from-kube.crt" "${workdir}/from-kube.key"

precheck_cert "${workdir}/from-kube.crt" "kubeconfig client cert should still be a cert"
precheck_key "${workdir}/from-kube.key" "kubeconfig client key should still be a key"
assert_chain_valid "${crypto_dir}/ca.crt" "${workdir}/from-kube.crt" \
    "kubeconfig client cert should verify against regenerated CA"
assert_summary_valid "${workdir}/summary.yaml"
