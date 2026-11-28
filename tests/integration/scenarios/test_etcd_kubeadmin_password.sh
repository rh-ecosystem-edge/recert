#!/usr/bin/env bash
# kubeadmin_password_hash: non-empty updates kube-system/kubeadmin, empty deletes it,
# and a non-empty hash without an existing Secret is a hard error.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_kubeadmin_password")
custom_dir="${workdir}/custom"
mkdir -p "$custom_dir"
setup_webhook_authenticator "$custom_dir"

etcd_key="/kubernetes.io/secrets/kube-system/kubeadmin"
trap 'etcd_del "$etcd_key"' EXIT

old_hash='$2a$10$oldseedhasholdseedhasholdseedhasholdseedhashold'
new_hash='$2a$10$newclusterhashnewclusterhashnewclusterhashnew'

etcd_put_json "$etcd_key" '{
  "apiVersion": "v1",
  "kind": "Secret",
  "type": "Opaque",
  "metadata": {"name": "kubeadmin", "namespace": "kube-system"},
  "data": {"kubeadmin": "'"$(printf '%s' "$old_hash" | base64 -w0)"'"}
}'
precheck_etcd_key "$etcd_key" "kubeadmin Secret seeded" >/dev/null

write_config() {
    cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${custom_dir}
kubeadmin_password_hash: '$1'
postprocess_only: true
EOF
}

# 1. Non-empty hash replaces the existing one. Recert writes the Secret back as
#    protobuf, so the raw hash bytes appear verbatim in the stored value.
write_config "$new_hash"
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null
assert_etcd_has "$etcd_key" "$new_hash" "kubeadmin Secret should carry the new hash"
assert_etcd_lacks "$etcd_key" "$old_hash" "kubeadmin Secret should not keep the seed hash"

# 2. Empty hash deletes the Secret, disabling password login.
write_config ""
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "deleting kubeadmin password secret as requested" \
    "empty hash should log the deletion"
assert_etcd_absent "$etcd_key" "kubeadmin Secret should be deleted for an empty hash"

# 3. Non-empty hash with no Secret to update is an error (recert never creates it).
write_config "$new_hash"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "kubeadmin" "missing-Secret failure should mention kubeadmin"
assert_etcd_absent "$etcd_key" "failed run must not create the kubeadmin Secret"
