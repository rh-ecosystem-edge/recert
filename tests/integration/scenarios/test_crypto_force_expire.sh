#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "crypto_force_expire")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

not_after_after=$(openssl x509 -noout -enddate -in "${crypto_dir}/ca.crt" 2>/dev/null | cut -d= -f2)
not_after_epoch=$(date -d "$not_after_after" +%s)
now_epoch=$(date +%s)

# force_expire sets notAfter to approximately "now", allow 60s margin
assert_lt "$not_after_epoch" "$((now_epoch + 60))" "force-expired cert should have notAfter near or in the past"
