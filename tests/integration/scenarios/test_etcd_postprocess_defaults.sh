#!/usr/bin/env bash
# Side effects of ocp_postprocess that run on every etcd recert run, independent of
# any cluster customization: lease and node-kubeconfigs deletion, ClusterVersion
# Available=False, the OLM packageserver CA hash annotation, and the apiserver
# Deployment dep-/spec-hash annotations.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_postprocess_defaults")
custom_dir="${workdir}/custom"
mkdir -p "$custom_dir"
setup_webhook_authenticator "$custom_dir"

# Earlier serial scenarios already post-processed the shared baseline. Re-seed it so
# this run starts from the stale annotations / Available=True state in seed_etcd.sh.
bash "${INTEGRATION_LIB_DIR}/../fixtures/seed_etcd.sh" >/dev/null

lease_key="/kubernetes.io/leases/kube-node-lease/test-node"
node_kubeconfigs_key="/kubernetes.io/secrets/openshift-kube-apiserver/node-kubeconfigs"
cvo_key="/kubernetes.io/config.openshift.io/clusterversions/version"
olm_secret_key="/kubernetes.io/secrets/openshift-operator-lifecycle-manager/packageserver-service-cert"
deployment_keys=(
    "/kubernetes.io/deployments/openshift-apiserver/apiserver"
    "/kubernetes.io/deployments/openshift-oauth-apiserver/apiserver"
)
trap 'etcd_del "$lease_key" "$node_kubeconfigs_key"' EXIT

etcd_put_json "$lease_key" '{
  "apiVersion": "coordination.k8s.io/v1",
  "kind": "Lease",
  "metadata": {"name": "test-node", "namespace": "kube-node-lease"},
  "spec": {"holderIdentity": "test-node"}
}'
etcd_put_json "$node_kubeconfigs_key" '{
  "apiVersion": "v1",
  "kind": "Secret",
  "metadata": {"name": "node-kubeconfigs", "namespace": "openshift-kube-apiserver"},
  "data": {"lb-ext.kubeconfig": "c2VlZA=="}
}'

cvo_available() {
    etcd_get "$cvo_key" | python3 -c '
import json, sys
for c in json.load(sys.stdin)["status"]["conditions"]:
    if c["type"] == "Available":
        print(c["status"], c.get("message", ""))
'
}

assert_eq "$(cvo_available)" "True Done" "precheck: ClusterVersion starts Available=True"
for key in "${deployment_keys[@]}"; do
    assert_etcd_has "$key" '"hash"' "precheck: ${key} starts with stale dep annotations"
    assert_etcd_lacks "$key" "operator.openshift.io/spec-hash" "precheck: ${key} starts without spec-hash"
done
assert_etcd_lacks "$olm_secret_key" "olmcahash" "precheck: OLM Secret starts without olmcahash"

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${custom_dir}
postprocess_only: true
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null

assert_etcd_absent "$lease_key" "leases should be deleted"
assert_etcd_absent "$node_kubeconfigs_key" "node-kubeconfigs Secret should be deleted"

assert_eq "$(cvo_available)" "False Cluster version status unknown" \
    "ClusterVersion Available should be reset to False"

# olmcahash is the hex sha256 of the APIService's base64-decoded caBundle.
expected_olm_hash=$(printf '%s' "dummy-ca-data" | sha256sum | awk '{print $1}')
assert_etcd_has "$olm_secret_key" "$expected_olm_hash" "OLM Secret olmcahash should match the APIService caBundle"

# The rewritten Deployments are protobuf-encoded: a surviving stale value would show up
# either as JSON ("hash") or as a protobuf string field (0x12, length 4, "hash").
for key in "${deployment_keys[@]}"; do
    assert_etcd_has "$key" "operator.openshift.io/spec-hash" "${key} should gain a spec-hash annotation"
    assert_etcd_lacks "$key" '"hash"' "${key} should not keep stale JSON dep annotations"
    assert_etcd_lacks "$key" $'\x12\x04hash' "${key} should not keep stale dep annotation values"
done
