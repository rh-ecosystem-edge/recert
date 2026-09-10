#!/usr/bin/env bash

set -euo pipefail

# This scenario exercises the PEM line-ending handling (`pem_bundle_line_ending`)
# on the etcd TLS-secret write-back path. The TLS secret rewrite goes through
# `commit_k8s_cert` -> `recreate_yaml_at_location_with_new_pem` ->
# `pem_bundle_replace_pem_at_index`, which detects the bundle's line ending style.
#
# Phase 1 (regression): a pure-CRLF bundle must survive the rewrite with CRLF
#   preserved.
# Phase 2 (discriminator): a bundle mixing CRLF and LF was mis-detected pre-fix as
#   pure CRLF (the state machine never saw a bare LF transition), so the run
#   silently succeeded and left the mixed endings in place. Post-fix, mixed (or
#   bare-CR) endings are rejected with a clean "mixed line endings" error.

workdir=$(setup_test_workdir "etcd_pem_crlf")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

setup_webhook_authenticator "$crypto_dir"

# Snapshot original bytes before recert mutates the crypto_dir
mkdir -p "${workdir}/orig"
cp "${crypto_dir}/server.crt" "${workdir}/orig/server.crt"
cp "${crypto_dir}/ca.crt" "${workdir}/orig/ca.crt"

# ── Phase 1: pure CRLF bundle ──

# Trap cleanup before the first write to the shared etcd key
trap 'etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/default/app-tls-crlf >/dev/null' EXIT

python3 - "${workdir}/orig/server.crt" "${workdir}/server_crlf.crt" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read().replace(b'\n', b'\r\n')
open(sys.argv[2], 'wb').write(data)
PY

etcd_put_tls_secret "default" "app-tls-crlf" \
    "${workdir}/server_crlf.crt" "${crypto_dir}/server.key"

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

etcd_secret_pems "/kubernetes.io/secrets/default/app-tls-crlf" \
    "${workdir}/from-etcd.crt" "${workdir}/from-etcd.key"

assert_ne "$(sha256_file "${workdir}/from-etcd.crt")" "$(sha256_file "${workdir}/orig/server.crt")" \
    "etcd tls.crt should be regenerated"
assert_chain_valid "${crypto_dir}/ca.crt" "${workdir}/from-etcd.crt" \
    "regenerated etcd leaf should verify against regenerated CA"

# The committed bundle must keep CRLF internally. NOTE: the test read-back
# (`etcd_secret_pems` -> `_pem_from_protobuf`) normalizes the *final* newline to
# a bare LF, so allow exactly one trailing LF beyond the CRLF pairs; any LF that
# recert actually emitted inside the bundle would show up as a second one
# (or a bare CR).
python3 - "${workdir}/from-etcd.crt" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read()
crlf = data.count(b'\r\n')
lf = data.count(b'\n')
cr = data.count(b'\r')
if not (crlf > 0 and cr == crlf and (lf - crlf) <= 1):
    print(f'CRLF not preserved: CRLF={crlf} LF={lf} CR={cr}')
    sys.exit(1)
PY

# ── Phase 2: mixed CRLF + LF bundle must fail cleanly ──
# Build a bundle whose first PEM (the regenerated server cert) uses CRLF and whose
# second PEM (the CA) keeps LF. Pre-fix this was mis-detected as pure CRLF and the
# run succeeded, leaving mixed endings in etcd.

cp "${workdir}/server_crlf.crt" "${workdir}/mixed_bundle.crt"
cat "${workdir}/orig/ca.crt" >> "${workdir}/mixed_bundle.crt"

etcd_put_tls_secret "default" "app-tls-crlf" \
    "${workdir}/mixed_bundle.crt" "${crypto_dir}/server.key"

# Separate summary file so the failed run cannot clobber phase 1's summary
cat > "${workdir}/config2.yaml" <<EOF
etcd_endpoint: localhost:2379
crypto_dirs:
  - ${crypto_dir}
cluster_customization_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary2.yaml
EOF

output=$(RECERT_CONFIG="${workdir}/config2.yaml" run_recert_expect_failure)
assert_contains "$output" "mixed line endings" \
    "mixed CRLF+LF bundle should be rejected with a line-ending error"

assert_summary_valid "${workdir}/summary.yaml"