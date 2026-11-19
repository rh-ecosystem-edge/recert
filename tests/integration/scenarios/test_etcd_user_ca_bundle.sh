#!/usr/bin/env bash
# user_ca_bundle and proxy_trusted_ca_bundle: the seed's additional trust bundle is
# replaced in openshift-config/user-ca-bundle, the MachineConfig/ControllerConfig copies
# and the on-disk anchor; with proxy_trusted_ca_bundle "user-ca-bundle:" the merged
# trusted-ca-bundle (new user bundle + the seed's system certs) is re-injected.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_user_ca_bundle")
custom_dir="${workdir}/custom"
mkdir -p "$custom_dir"
setup_webhook_authenticator "$custom_dir"

certs_dir="${workdir}/certs"
mkdir -p "$certs_dir"
for name in old-user new-user system; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj "/CN=${name}-ca" -keyout /dev/null -out "${certs_dir}/${name}.crt" 2>/dev/null
done
old_user=$(cat "${certs_dir}/old-user.crt")
new_user=$(cat "${certs_dir}/new-user.crt")
system=$(cat "${certs_dir}/system.crt")
# A line from the middle of each PEM identifies it inside protobuf-encoded values.
pem_id() { sed -n 4p "${certs_dir}/$1.crt"; }

user_ca_key="/kubernetes.io/configmaps/openshift-config/user-ca-bundle"
merged_key="/kubernetes.io/configmaps/openshift-config-managed/trusted-ca-bundle"
ccm_key="/kubernetes.io/configmaps/openshift-cloud-controller-manager/ccm-trusted-ca"
labeled_key="/kubernetes.io/configmaps/openshift-test/injected-trusted-ca"
unlabeled_key="/kubernetes.io/configmaps/openshift-test/not-injected"
kcm_user_ca_key="/kubernetes.io/configmaps/openshift-controller-manager/openshift-user-ca"
proxy_key="/kubernetes.io/config.openshift.io/proxies/cluster"
cc_key="/kubernetes.io/machineconfiguration.openshift.io/controllerconfigs/machine-config-controller"
mc_key="/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/99-test-user-ca"
anchor_path="/etc/pki/ca-trust/source/anchors/openshift-config-user-ca-bundle.crt"
anchor_file="${custom_dir}${anchor_path}"
static_merged_file="${custom_dir}/static-pod-resources/configmaps/trusted-ca-bundle/ca-bundle.crt"

restore_baseline() {
    etcd_del "$user_ca_key" "$ccm_key" "$labeled_key" "$unlabeled_key" "$kcm_user_ca_key" "$proxy_key" "$cc_key" "$mc_key"
    # seed_etcd.sh baseline: an empty merged bundle, required by discover_external_certs().
    put_configmap "$merged_key" "" ""
}

# put_configmap KEY CA_BUNDLE LABELS_JSON
put_configmap() {
    local ns name
    ns=$(cut -d/ -f4 <<<"$1")
    name=$(cut -d/ -f5 <<<"$1")
    etcd_put_json "$1" "$(python3 -c '
import json, sys
ns, name, bundle, labels = sys.argv[1:5]
print(json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": name, "namespace": ns, "labels": json.loads(labels or "{}")},
                  "data": {"ca-bundle.crt": bundle}}))
' "$ns" "$name" "$2" "$3")"
}

seed() {
    put_configmap "$user_ca_key" "${old_user}"$'\n' ""
    put_configmap "$merged_key" "${old_user}"$'\n'"${system}"$'\n' ""
    put_configmap "$ccm_key" "${old_user}"$'\n'"${system}"$'\n' ""
    put_configmap "$labeled_key" "${old_user}"$'\n'"${system}"$'\n' '{"config.openshift.io/inject-trusted-cabundle": "true"}'
    put_configmap "$unlabeled_key" "${old_user}"$'\n' ""
    put_configmap "$kcm_user_ca_key" "${old_user}"$'\n' ""
    etcd_put_json "$proxy_key" '{
  "apiVersion": "config.openshift.io/v1",
  "kind": "Proxy",
  "metadata": {"name": "cluster"},
  "spec": {"trustedCA": {"name": "user-ca-bundle"}},
  "status": {}
}'
    etcd_put_json "$cc_key" '{
  "apiVersion": "machineconfiguration.openshift.io/v1",
  "kind": "ControllerConfig",
  "metadata": {"name": "machine-config-controller"},
  "spec": {"additionalTrustBundle": "'"$(base64 -w0 < "${certs_dir}/old-user.crt")"'"}
}'
    etcd_put_json "$mc_key" "$(machineconfig_json 99-test-user-ca "$anchor_path" "${old_user}"$'\n')"
    mkdir -p "$(dirname "$anchor_file")" "$(dirname "$static_merged_file")"
    printf '%s\n' "$old_user" > "$anchor_file"
    printf '%s\n%s\n' "$old_user" "$system" > "$static_merged_file"
}

trap restore_baseline EXIT

indent() { sed 's/^/  /'; }

write_config() {
    cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${custom_dir}
postprocess_only: true
$1
EOF
}

user_ca_config="user_ca_bundle: |
$(printf '%s\n' "$new_user" | indent)"

# 1. user_ca_bundle alone.
seed
write_config "$user_ca_config"
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null

assert_etcd_has "$user_ca_key" "$(pem_id new-user)" "user-ca-bundle ConfigMap should hold the new bundle"
assert_etcd_lacks "$user_ca_key" "$(pem_id old-user)" "user-ca-bundle ConfigMap should drop the seed bundle"
assert_eq "$(etcd_get "$cc_key" | python3 -c 'import base64,json,sys; sys.stdout.write(base64.b64decode(json.load(sys.stdin)["spec"]["additionalTrustBundle"]).decode())')" \
    "$new_user" "ControllerConfig additionalTrustBundle should be the new bundle"
assert_eq "$(etcd_mc_file "$mc_key" "$anchor_path")" "$new_user" "MachineConfig anchor should be the new bundle"
assert_eq "$(cat "$anchor_file")" "$new_user" "on-disk anchor should be the new bundle"
assert_etcd_has "$merged_key" "$(pem_id old-user)" "merged bundle is only rewritten with proxy_trusted_ca_bundle"

# 2. user_ca_bundle + proxy_trusted_ca_bundle "user-ca-bundle:" (the bundle comes from
#    user_ca_bundle): every injected copy becomes new user bundle + the seed's system certs.
restore_baseline
seed
write_config "${user_ca_config}
proxy_trusted_ca_bundle: 'user-ca-bundle:'"
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null

for key in "$merged_key" "$ccm_key" "$labeled_key"; do
    assert_etcd_has "$key" "$(pem_id new-user)" "${key}: merged bundle should contain the new user bundle"
    assert_etcd_has "$key" "$(pem_id system)" "${key}: merged bundle should keep the seed's system certs"
    assert_etcd_lacks "$key" "$(pem_id old-user)" "${key}: merged bundle should drop the seed user bundle"
done
assert_etcd_has "$unlabeled_key" "$(pem_id old-user)" "unlabeled ConfigMaps must not be injected"
assert_etcd_has "$kcm_user_ca_key" "$(pem_id new-user)" "openshift-user-ca should hold the new user bundle"
assert_contains "$(cat "$static_merged_file")" "$new_user" "static trusted-ca-bundle file should hold the new user bundle"
assert_contains "$(cat "$static_merged_file")" "$system" "static trusted-ca-bundle file should keep system certs"
assert_not_contains "$(cat "$static_merged_file")" "$old_user" "static trusted-ca-bundle file should drop the seed user bundle"

# 3. "user-ca-bundle:<pem>" is rejected: that bundle must come from user_ca_bundle.
restore_baseline
seed
write_config "${user_ca_config}
proxy_trusted_ca_bundle: |
  user-ca-bundle:$(printf '%s\n' "$new_user" | indent | sed '1s/^  //')"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "user-ca-bundle configmap name requires ca-bundle to be empty" \
    "user-ca-bundle with an explicit bundle should be rejected"

# 4. user_ca_bundle on a cluster without a user-ca-bundle ConfigMap is an error.
etcd_del "$user_ca_key"
write_config "$user_ca_config"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "no configmap" "missing user-ca-bundle ConfigMap should be an error"
