#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_connect")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)

setup_webhook_authenticator "$crypto_dir"

# Prechecks
precheck_cert "${crypto_dir}/ca.crt"
precheck_etcd_key "/kubernetes.io/config.openshift.io/apiservers/cluster" "APIServer/cluster seeded"
precheck_etcd_key "/kubernetes.io/secrets/openshift-kube-apiserver/webhook-authenticator" "webhook secret seeded"
assert_file_exists "${crypto_dir}/kube-apiserver-pod-1/webhook-authenticator/kubeConfig" "webhook kubeConfig exists"

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
crypto_dirs:
  - ${crypto_dir}
cluster_customization_dirs:
  - ${crypto_dir}
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

# Recert connects, scans, and recertifies successfully, but
# ocp_postprocess fails on missing OCP operator resources (expected
# without a full OCP cluster). We verify it got past connection,
# scanning, and crypto regeneration.
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "Connected to etcd" "should connect to etcd"
assert_contains "$output" "Regenerated all crypto objects" "should complete crypto regeneration"
assert_contains "$output" "Committing cryptographic objects" "should commit crypto objects"
