#!/usr/bin/env bash
# pull_secret happy path: the new pull secret replaces the seed's credentials in the
# openshift-config/pull-secret Secret, in MachineConfigs that carry
# /var/lib/kubelet/config.json, and in the on-disk kubelet config.json.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_pull_secret_rename")
kubelet_dir="${workdir}/kubelet"
mkdir -p "$kubelet_dir"
setup_webhook_authenticator "$kubelet_dir"

secret_key="/kubernetes.io/secrets/openshift-config/pull-secret"
mc_key="/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/99-test-pull-secret"
unrelated_mc_key="/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/99-test-unrelated"
trap 'etcd_del "$secret_key" "$mc_key" "$unrelated_mc_key"' EXIT

old_pull_secret='{"auths":{"seed-registry.example.com":{"auth":"c2VlZDpzZWNyZXQ="}}}'
new_pull_secret='{"auths":{"new-registry.example.com":{"auth":"bmV3OnNlY3JldA=="}}}'

etcd_put_json "$secret_key" '{
  "apiVersion": "v1",
  "kind": "Secret",
  "type": "kubernetes.io/dockerconfigjson",
  "metadata": {"name": "pull-secret", "namespace": "openshift-config"},
  "data": {".dockerconfigjson": "'"$(printf '%s' "$old_pull_secret" | base64 -w0)"'"}
}'
etcd_put_json "$mc_key" "$(machineconfig_json 99-test-pull-secret /var/lib/kubelet/config.json "$old_pull_secret")"
etcd_put_json "$unrelated_mc_key" "$(machineconfig_json 99-test-unrelated /etc/unrelated.conf "seed-registry.example.com")"
printf '%s' "$old_pull_secret" > "${kubelet_dir}/config.json"

assert_eq "$(etcd_mc_file "$mc_key" /var/lib/kubelet/config.json)" "$old_pull_secret" \
    "precheck: MachineConfig carries the seed pull secret"

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${kubelet_dir}
pull_secret: '${new_pull_secret}'
postprocess_only: true
EOF

RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null

# The Secret is written back as protobuf with .dockerconfigjson as raw bytes.
assert_etcd_has "$secret_key" "new-registry.example.com" "pull-secret Secret should hold the new registry"
assert_etcd_lacks "$secret_key" "seed-registry.example.com" "pull-secret Secret should drop the seed registry"

assert_eq "$(etcd_mc_file "$mc_key" /var/lib/kubelet/config.json)" "$new_pull_secret" \
    "MachineConfig kubelet config.json should be the new pull secret"
assert_eq "$(etcd_mc_file "$unrelated_mc_key" /etc/unrelated.conf)" "seed-registry.example.com" \
    "MachineConfig without kubelet config.json should be untouched"

assert_eq "$(cat "${kubelet_dir}/config.json")" "$new_pull_secret" \
    "on-disk kubelet config.json should be the new pull secret"
