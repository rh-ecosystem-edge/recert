#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_tls_secret_regen")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

setup_webhook_authenticator "$crypto_dir"

# Trap cleanup before the first write to the shared etcd key
trap 'etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/default/app-tls >/dev/null' EXIT

etcd_put_tls_secret "default" "app-tls" \
    "${crypto_dir}/server.crt" "${crypto_dir}/server.key"

# Attach a non-PEM byte-array data field holding multi-byte UTF-8 bytes
# ([0xE2,0x9C,0x93] = U+2713). Due to Kubernetes Secret JSON round-tripping this
# field is NOT observably corrupted by the per-byte `as char` decode (the value is
# only touched by recert when the tls.crt/tls.key locations are rewired, which are
# always ASCII PEM). Regression coverage for the ByteArray decode path only -- the
# real coverage for the from_utf8 fix lives in the PR's unit tests.
utf8_payload=$(etcd_get "/kubernetes.io/secrets/default/app-tls" | python3 -c '
import json, sys
d = json.load(sys.stdin)
d["data"]["utf8-field"] = [0xE2, 0x9C, 0x93]
json.dump(d, sys.stdout, separators=(",", ":"))
')
etcd_put_json "/kubernetes.io/secrets/default/app-tls" "$utf8_payload"

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

# The multi-byte UTF-8 byte-array field must survive the edit cycle intact. The
# check searches the RAW etcd bytes (not JSON) because on this branch the rewritten
# secret is committed back to etcd as protobuf, which `json.load` cannot parse; the
# data field is carried verbatim as bytes under either encoding.
etcd_get "/kubernetes.io/secrets/default/app-tls" | python3 -c '
import sys
raw = sys.stdin.buffer.read()
if b"\xe2\x9c\x93" not in raw:
    raise SystemExit("utf8-field [0xE2,0x9C,0x93] missing from committed secret")
'

assert_summary_valid "${workdir}/summary.yaml"
