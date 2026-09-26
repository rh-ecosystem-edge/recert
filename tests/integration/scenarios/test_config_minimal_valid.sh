#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "config_minimal_valid")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)

cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
dry_run: true
summary_file: ${workdir}/summary.yaml
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

assert_summary_valid "${workdir}/summary.yaml"
