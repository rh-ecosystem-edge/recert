#!/usr/bin/env bash

# Rename the etcd static pod hostname with a seed hostname that used to be rejected
# ("existing") while the rendered pod contains unrelated values ("REVISION", "true") that a
# document-wide `value:` substitution would have corrupted.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_hostname_rename")
cluster_dir="${workdir}/cluster"
old_hostname="existing"
new_hostname="node2"
etcd_endpoint="${ETCD_ENDPOINT:-localhost:2379}"

pod_yaml=$(cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: etcd
  labels:
    etcd: "true"
spec:
  initContainers:
  - name: etcd-ensure-env-vars
    env:
    - name: "ETCD_STATIC_POD_VERSION"
      value: "REVISION"
    - name: "NODE_${old_hostname}_ETCD_NAME"
      value: "${old_hostname}"
  containers:
  - name: etcd
    env:
    - name: "NODE_${old_hostname}_ETCD_NAME"
      value: "${old_hostname}"
    - name: "NODE_${old_hostname}_ETCD_URL_HOST"
      value: "192.0.2.10"
    - name: "NODE_${old_hostname}_IP"
      value: "192.0.2.10"
    - name: "SOME_UNRELATED_BOOLEAN"
      value: "true"
    command:
    - /bin/sh
    - -c
    - exec etcd --target-name=${old_hostname} --cert=/etc/kubernetes/static-pod-certs/secrets/etcd-all-certs/etcd-peer-${old_hostname}.crt
EOF
)

trap '
  etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" \
    /kubernetes.io/secrets/openshift-etcd/etcd-all-certs \
    /kubernetes.io/configmaps/openshift-etcd/etcd-pod \
    /kubernetes.io/configmaps/openshift-etcd/etcd-scripts \
    /kubernetes.io/operator.openshift.io/kubeapiservers/cluster \
    /kubernetes.io/operator.openshift.io/kubeschedulers/cluster \
    /kubernetes.io/operator.openshift.io/kubecontrollermanagers/cluster \
    /kubernetes.io/operator.openshift.io/etcds/cluster >/dev/null 2>&1 || true
' EXIT

# fix_etcd_all_certs derives the original hostname from the etcd-peer-*.crt data key
etcd_put_json "/kubernetes.io/secrets/openshift-etcd/etcd-all-certs" "{
  \"apiVersion\": \"v1\",
  \"kind\": \"Secret\",
  \"metadata\": {\"name\": \"etcd-all-certs\", \"namespace\": \"openshift-etcd\"},
  \"data\": {
    \"etcd-peer-${old_hostname}.crt\": [],
    \"etcd-peer-${old_hostname}.key\": [],
    \"etcd-serving-${old_hostname}.crt\": [],
    \"etcd-serving-${old_hostname}.key\": []
  }
}"

etcd_pod_configmap=$(printf '%s' "$pod_yaml" | python3 -c '
import json, sys
print(json.dumps({
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {"name": "etcd-pod", "namespace": "openshift-etcd"},
  "data": {"pod.yaml": sys.stdin.read()},
}))
')
etcd_put_json "/kubernetes.io/configmaps/openshift-etcd/etcd-pod" "$etcd_pod_configmap"

# fix_etcd_scripts reads etcd.env unconditionally
etcd_put_json "/kubernetes.io/configmaps/openshift-etcd/etcd-scripts" "{
  \"apiVersion\": \"v1\",
  \"kind\": \"ConfigMap\",
  \"metadata\": {\"name\": \"etcd-scripts\", \"namespace\": \"openshift-etcd\"},
  \"data\": {\"etcd.env\": \"export NODE_${old_hostname}_ETCD_NAME=\\\"${old_hostname}\\\"\nexport NODE_${old_hostname}_ETCD_URL_HOST=\nexport NODE_${old_hostname}_IP=\n\"}
}"

for entry in "KubeAPIServer/kubeapiservers" "KubeScheduler/kubeschedulers" \
             "KubeControllerManager/kubecontrollermanagers" "Etcd/etcds"; do
  kind="${entry%%/*}"
  plural="${entry##*/}"
  etcd_put_json "/kubernetes.io/operator.openshift.io/${plural}/cluster" "{
    \"apiVersion\": \"operator.openshift.io/v1\",
    \"kind\": \"${kind}\",
    \"metadata\": {\"name\": \"cluster\"},
    \"status\": {\"nodeStatuses\": [{\"nodeName\": \"${old_hostname}\"}]}
  }"
done

mkdir -p "${cluster_dir}/configmaps/etcd-pod"
printf '%s\n' "$pod_yaml" > "${cluster_dir}/configmaps/etcd-pod/pod.yaml"

# The webhook-authenticator sync runs before the rename and needs a kube-apiserver-pod-* dir
setup_webhook_authenticator "$cluster_dir"

precheck_etcd_key "/kubernetes.io/secrets/openshift-etcd/etcd-all-certs" "etcd-all-certs should be seeded" >/dev/null
precheck_etcd_key "/kubernetes.io/configmaps/openshift-etcd/etcd-pod" "etcd-pod should be seeded" >/dev/null

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: ${etcd_endpoint}
postprocess_only: true
cluster_customization_dirs:
  - ${cluster_dir}
hostname: ${new_hostname}
summary_file: ${workdir}/summary.yaml
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "Committing to actual etcd" "recert should commit to etcd"

# Edited ConfigMaps are written back as protobuf, so assert on raw bytes rather than JSON
raw_pod=$(etcd_get "/kubernetes.io/configmaps/openshift-etcd/etcd-pod")
assert_contains "$raw_pod" "NODE_${new_hostname}_ETCD_NAME" "env var name should be renamed"
assert_contains "$raw_pod" "value: \"${new_hostname}\"" "ETCD_NAME value should be renamed"
assert_contains "$raw_pod" "--target-name=${new_hostname}" "target-name should be renamed"
assert_contains "$raw_pod" "etcd-peer-${new_hostname}.crt" "peer cert path should be renamed"
assert_not_contains "$raw_pod" "NODE_${old_hostname}_" "old env var name must be gone"

# Values that merely collide with the old hostname must survive
assert_contains "$raw_pod" "value: \"REVISION\"" "ETCD_STATIC_POD_VERSION value must be untouched"
assert_contains "$raw_pod" "SOME_UNRELATED_BOOLEAN" "unrelated env var must be untouched"
assert_contains "$raw_pod" "value: \"true\"" "unrelated value must be untouched"
assert_contains "$raw_pod" "value: \"192.0.2.10\"" "IP env values must be untouched"

# The etcd-all-certs data keys are renamed too
raw_certs=$(etcd_get "/kubernetes.io/secrets/openshift-etcd/etcd-all-certs")
assert_contains "$raw_certs" "etcd-peer-${new_hostname}.crt" "peer cert data key should be renamed"
assert_not_contains "$raw_certs" "etcd-peer-${old_hostname}.crt" "old peer cert data key must be gone"

# operator.openshift.io nodeStatuses are rewritten
raw_etcds=$(etcd_get "/kubernetes.io/operator.openshift.io/etcds/cluster")
assert_contains "$raw_etcds" "${new_hostname}" "etcds/cluster nodeStatus nodeName should be renamed"

# The on-disk pod.yaml is rewritten by the filesystem pass
disk_pod=$(cat "${cluster_dir}/configmaps/etcd-pod/pod.yaml")
assert_contains "$disk_pod" "NODE_${new_hostname}_ETCD_NAME" "disk pod.yaml env name should be renamed"
assert_contains "$disk_pod" "value: \"${new_hostname}\"" "disk pod.yaml value should be renamed"
assert_not_contains "$disk_pod" "NODE_${old_hostname}_" "disk pod.yaml old name must be gone"
assert_contains "$disk_pod" "value: \"REVISION\"" "disk pod.yaml unrelated value must be untouched"

assert_summary_valid "${workdir}/summary.yaml"
