#!/usr/bin/env bash

set -euo pipefail

# Discriminates #1937: Encoding::Json must stay JSON on etcd write-back.
# Pre-fix main re-encodes known kinds (Secret) as protobuf (k8s\x00…).

workdir=$(setup_test_workdir "etcd_json_encode")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

setup_webhook_authenticator "$crypto_dir"

ETCD_KEY="/kubernetes.io/secrets/default/json-encode-tls"
trap 'etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/default/json-encode-tls >/dev/null 2>&1 || true' EXIT

etcd_put_tls_secret "default" "json-encode-tls" \
    "${crypto_dir}/server.crt" "${crypto_dir}/server.key"

precheck_etcd_key "$ETCD_KEY" "TLS secret seeded as JSON"
assert_match "$(etcd_get "$ETCD_KEY")" '^\{' \
    "precheck: seeded secret must start as JSON"

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

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

etcd_secret_pems "$ETCD_KEY" \
    "${workdir}/from-etcd.crt" "${workdir}/from-etcd.key"
precheck_cert "${workdir}/from-etcd.crt" "etcd tls.crt should still be a cert"
precheck_key "${workdir}/from-etcd.key" "etcd tls.key should still be a key"
assert_ne "$(sha256_file "${workdir}/from-etcd.crt")" "$orig_cert_hash" \
    "etcd tls.crt should be regenerated"
assert_ne "$(sha256_file "${workdir}/from-etcd.key")" "$orig_key_hash" \
    "etcd tls.key should be regenerated"

# The discriminating assert: JSON-mode values must not become protobuf.
assert_match "$(etcd_get "$ETCD_KEY")" '^\{' \
    "rewritten TLS secret should stay JSON-encoded in etcd (not protobuf)"

assert_summary_valid "${workdir}/summary.yaml"
