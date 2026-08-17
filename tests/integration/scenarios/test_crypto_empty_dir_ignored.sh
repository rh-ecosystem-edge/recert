#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_empty_dir_ignored")
crypto_dir=$(setup_crypto_dir "$workdir" \
    rsa4096-ca.crt rsa4096-ca.key rsa4096-server.crt rsa4096-server.key)

empty_dir="${crypto_dir}/var/lib/kubelet/pods/abc/volumes/kubernetes.io~empty-dir/data"
mkdir -p "$empty_dir"
cp "${FIXTURES_DIR}/ca.crt" "${empty_dir}/ca.crt"
cp "${FIXTURES_DIR}/ca.key" "${empty_dir}/ca.key"
cp "${FIXTURES_DIR}/server.crt" "${empty_dir}/server.crt"
cp "${FIXTURES_DIR}/server.key" "${empty_dir}/server.key"

empty_cert_hash=$(sha256_file "${empty_dir}/server.crt")
empty_key_hash=$(sha256_file "${empty_dir}/server.key")
real_cert_hash=$(sha256_file "${crypto_dir}/rsa4096-server.crt")
real_key_hash=$(sha256_file "${crypto_dir}/rsa4096-server.key")

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_file_unchanged "${empty_dir}/server.crt" "$empty_cert_hash" \
    "certs under kubernetes.io~empty-dir should be ignored"
assert_file_unchanged "${empty_dir}/server.key" "$empty_key_hash" \
    "keys under kubernetes.io~empty-dir should be ignored"
assert_ne "$(sha256_file "${crypto_dir}/rsa4096-server.crt")" "$real_cert_hash" \
    "sibling tree outside empty-dir should still be regenerated"
assert_ne "$(sha256_file "${crypto_dir}/rsa4096-server.key")" "$real_key_hash" \
    "sibling key outside empty-dir should still be regenerated"
assert_summary_valid "${workdir}/summary.yaml"
