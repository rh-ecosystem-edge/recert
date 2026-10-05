#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_invalid_kubelet_pull_secret")
kubelet_dir="${workdir}/kubelet"
etcd_key="/kubernetes.io/secrets/openshift-config/pull-secret"
mkdir -p "${kubelet_dir}/node-a" "${kubelet_dir}/node-b"
setup_webhook_authenticator "${kubelet_dir}"

cat > "${kubelet_dir}/node-a/config.json" <<'JSON'
{"auths":{"registry.example.com":{}}}
JSON
cat > "${kubelet_dir}/node-b/config.json" <<'JSON'
not valid json
JSON

trap 'etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" "${etcd_key}" >/dev/null' EXIT

old_pull_secret_b64=$(printf '%s' '{"auths":{"registry.example.com":{}}}' | base64 -w0)
etcd_put_json "${etcd_key}" '{
  "apiVersion": "v1",
  "kind": "Secret",
  "type": "kubernetes.io/dockerconfigjson",
  "metadata": {"name": "pull-secret", "namespace": "openshift-config"},
  "data": {".dockerconfigjson": "'"${old_pull_secret_b64}"'"}
}'
etcd_before=$(etcd_get "${etcd_key}")
invalid_before=$(sha256_file "${kubelet_dir}/node-b/config.json")
new_pull_secret='{"auths":{"replacement":{}}}'

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${kubelet_dir}
pull_secret: '${new_pull_secret}'
postprocess_only: true
EOF

# recert should succeed: the invalid config.json is skipped with a warning and
# the valid one is overwritten
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "skipping" "invalid kubelet config should produce a skip warning"
assert_ne "$(etcd_get "${etcd_key}")" "$etcd_before" "pull-secret Secret in etcd should be updated"
assert_contains "$(cat "${kubelet_dir}/node-a/config.json")" "replacement" \
    "valid kubelet config should be overwritten with the new pull secret"
assert_file_unchanged "${kubelet_dir}/node-b/config.json" "$invalid_before" \
    "invalid kubelet config should remain unchanged (skipped)"
