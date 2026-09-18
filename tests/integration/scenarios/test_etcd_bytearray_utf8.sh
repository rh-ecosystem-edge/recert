#!/usr/bin/env bash

set -euo pipefail

# Discriminates #1938: ByteArray decode must use from_utf8, not per-byte `as char`.
# Append multi-byte UTF-8 after the PEM in a ByteArray tls.crt field. Recert
# rewrites the PEM via decode_resource_data_entry; the trailing UTF-8 must survive.

workdir=$(setup_test_workdir "etcd_bytearray_utf8")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

setup_webhook_authenticator "$crypto_dir"

ETCD_KEY="/kubernetes.io/secrets/default/bytearray-utf8-tls"
trap 'etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/default/bytearray-utf8-tls >/dev/null 2>&1 || true' EXIT

# Seed TLS secret then append U+2713 (E2 9C 93) after the PEM bytes in tls.crt.
etcd_put_tls_secret "default" "bytearray-utf8-tls" \
    "${crypto_dir}/server.crt" "${crypto_dir}/server.key"

utf8_payload=$(etcd_get "$ETCD_KEY" | python3 -c '
import json, sys
d = json.load(sys.stdin)
# tls.crt is a ByteArray (list of ints) from k8s_json.tls_secret
crt = d["data"]["tls.crt"]
if not isinstance(crt, list):
    raise SystemExit("expected ByteArray tls.crt")
# Append multi-byte UTF-8 checkmark after the PEM; comment-like trailer
crt.extend([0x0A, 0xE2, 0x9C, 0x93, 0x0A])
d["data"]["tls.crt"] = crt
json.dump(d, sys.stdout, separators=(",", ":"))
')
etcd_put_json "$ETCD_KEY" "$utf8_payload"

precheck_etcd_key "$ETCD_KEY" "TLS secret with UTF-8 trailer seeded"
etcd_get "$ETCD_KEY" | python3 -c '
import sys
raw = sys.stdin.buffer.read()
if b"\xe2\x9c\x93" not in raw:
    raise SystemExit("precheck: utf8 trailer missing from seeded secret")
'

orig_cert_hash=$(sha256_file "${crypto_dir}/server.crt")

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

# Regenerated cert must still be extractable (PEM portion rewritten)
etcd_secret_pems "$ETCD_KEY" \
    "${workdir}/from-etcd.crt" "${workdir}/from-etcd.key"
precheck_cert "${workdir}/from-etcd.crt" "etcd tls.crt should still be a cert"
assert_ne "$(sha256_file "${workdir}/from-etcd.crt")" "$orig_cert_hash" \
    "etcd tls.crt should be regenerated"

# Discriminating assert: multi-byte UTF-8 trailer must survive PEM rewrite.
# Search RAW etcd bytes (JSON or protobuf) for the original 3-byte sequence.
# Per-byte `as char` expands E2 9C 93 into different UTF-8 — this fails on main.
etcd_get "$ETCD_KEY" | python3 -c '
import sys
raw = sys.stdin.buffer.read()
if b"\xe2\x9c\x93" not in raw:
    raise SystemExit(
        "utf8 trailer [0xE2,0x9C,0x93] missing after rewrite "
        "(ByteArray decode likely used per-byte as char)"
    )
'

assert_summary_valid "${workdir}/summary.yaml"
