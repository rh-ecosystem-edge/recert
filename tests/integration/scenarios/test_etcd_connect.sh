#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_connect")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)

setup_webhook_authenticator "$crypto_dir"

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

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "Connected to etcd" "should connect to etcd"
assert_contains "$output" "Regenerated all crypto objects" "should complete crypto regeneration"
assert_contains "$output" "Committing to actual etcd" "should persist etcd cache"
assert_contains "$output" "All done" "should finish successfully"

cvo=$(etcd_get "/kubernetes.io/config.openshift.io/clusterversions/version")
assert_contains "$cvo" '"status":"False"' "CVO Available should be set to False"
assert_summary_valid "${workdir}/summary.yaml"
