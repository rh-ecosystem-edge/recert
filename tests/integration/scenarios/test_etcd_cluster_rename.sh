#!/usr/bin/env bash
# cluster_rename '<name>:<base_domain>[:<infra_id>]': every reference to the seed's
# cluster domain, API URLs, apps domain and infra ID is rewritten in etcd and in on-disk
# kubeconfigs / apiserver-url.env. Seeds the minimum set of objects the rename requires
# (lib/cluster_rename_fixtures.py) and re-seeds the shared baseline on exit.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_cluster_rename")
custom_dir="${workdir}/custom"
mkdir -p "$custom_dir"
setup_webhook_authenticator "$custom_dir"

old_name="seed"
old_base="old-base.example.com"
old_domain="${old_name}.${old_base}"
old_infra="seed-a1b2c"
new_name="renamed"
new_base="new-base.example.org"
new_domain="${new_name}.${new_base}"
new_infra="renamed-x9y8z"

fixture_json=$(python3 "${INTEGRATION_LIB_DIR}/cluster_rename_fixtures.py" "$old_name" "$old_base" "$old_infra")
fixture_keys=()
while IFS=$'\t' read -r key _; do
    fixture_keys+=("$key")
done <<< "$fixture_json"
extra_kas_config_key="/kubernetes.io/configmaps/openshift-kube-apiserver/config-malformed"
apiserver_url_mc_key="/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/99-apiserver-url-inline"

# Rewrites every fixture, so a negative case that fails part-way through a rename
# can be followed by a clean starting state.
seed_fixtures() {
    local key json
    while IFS=$'\t' read -r key json; do
        etcd_put_json "$key" "$json"
    done <<< "$fixture_json"
}

restore_baseline() {
    etcd_del "${fixture_keys[@]}" "$extra_kas_config_key" "$apiserver_url_mc_key"
    bash "${INTEGRATION_LIB_DIR}/../fixtures/seed_etcd.sh" >/dev/null
}
trap restore_baseline EXIT

seed_fixtures

kubeconfig="${custom_dir}/kubelet/kubeconfig"
apiserver_url_env="${custom_dir}/etc/kubernetes/apiserver-url.env"
mkdir -p "$(dirname "$kubeconfig")" "$(dirname "$apiserver_url_env")"
cat > "$kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://api-int.${old_domain}:6443
  name: ${old_name}
contexts:
- context:
    cluster: ${old_name}
    user: kubelet
  name: kubelet
current-context: kubelet
users:
- name: kubelet
  user: {}
EOF
printf "KUBERNETES_SERVICE_HOST='api-int.%s'\nKUBERNETES_SERVICE_PORT='6443'\n" "$old_domain" > "$apiserver_url_env"

write_config() {
    cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${custom_dir}
postprocess_only: true
cluster_rename: '$1'
EOF
}

# 1. A malformed value is rejected before anything is touched.
write_config "${new_name}"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "expected two or three parts separated by ':'" "one-part cluster_rename should be rejected"

# 2. A configmap that the rename enumerates but that has no config.yaml must be a
#    clean error. Indexing the data map directly used to panic here.
etcd_put_json "$extra_kas_config_key" '{"apiVersion": "v1", "kind": "ConfigMap",
  "metadata": {"name": "config-malformed", "namespace": "openshift-kube-apiserver"},
  "data": {"other.yaml": "foo: bar"}}'
write_config "${new_name}:${new_base}:${new_infra}"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "config.yaml not found" "a kube-apiserver configmap without config.yaml should fail cleanly"
assert_not_contains "$output" "panicked" "a missing config.yaml key must not panic"
etcd_del "$extra_kas_config_key"
seed_fixtures

# 3. A cluster-config-v1 without install-config must also fail cleanly.
etcd_put_json "/kubernetes.io/configmaps/openshift-etcd/cluster-config-v1" '{"apiVersion": "v1", "kind": "ConfigMap",
  "metadata": {"name": "cluster-config-v1", "namespace": "openshift-etcd"}, "data": {}}'
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "install-config not found" "a cluster-config-v1 without install-config should fail cleanly"
assert_not_contains "$output" "panicked" "a missing install-config key must not panic"
seed_fixtures

# 4. A MachineConfig file that uses inline contents instead of source (valid
#    Ignition) must fail cleanly rather than panic on the missing key.
etcd_put_json "$apiserver_url_mc_key" '{"apiVersion": "machineconfiguration.openshift.io/v1", "kind": "MachineConfig",
  "metadata": {"name": "99-apiserver-url-inline"},
  "spec": {"config": {"storage": {"files": [{"path": "/etc/kubernetes/apiserver-url.env",
    "contents": {"compression": "", "inline": "Rk9PPWJhcgo="}}]}}}}'
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "source not found" "inline file contents without source should fail cleanly"
assert_not_contains "$output" "panicked" "a missing source key must not panic"
etcd_del "$apiserver_url_mc_key"
seed_fixtures

# 5. Full rename with an explicit infra ID.
write_config "${new_name}:${new_base}:${new_infra}"
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null

# Every seeded object that still exists must have dropped the old domain and infra ID.
# The rename may rename keys (e.g. router-certs data) but never deletes these objects.
for key in "${fixture_keys[@]}"; do
    precheck_etcd_key "$key" "${key} should still exist after the rename" >/dev/null
    assert_etcd_lacks "$key" "$old_domain" "${key}: should not reference ${old_domain}"
    assert_etcd_lacks "$key" "$old_infra" "${key}: should not reference ${old_infra}"
done

# The OAuthClient fixtures seed managedFields[].fieldsV1.raw as a JSON numeric byte array,
# where a domain is invisible to text search. recert re-encodes them as protobuf on commit,
# turning raw into literal bytes, so the loop above does cover it. Prove that by matching
# text that only exists inside the managed field ('v:\"<uri>\"').
for client in openshift-browser-client openshift-challenging-client; do
    assert_etcd_has "/openshift.io/oauth/clients/${client}" "v:\\\"https://oauth-openshift.apps.${new_domain}/" \
        "${client} managedFields should be readable as text and use the new apps domain"
done

field() { etcd_json_pointer "$@"; }
assert_eq "$(field /kubernetes.io/config.openshift.io/dnses/cluster /spec/baseDomain)" "$new_domain" \
    "DNS baseDomain should be the new cluster domain"
assert_eq "$(field /kubernetes.io/config.openshift.io/infrastructures/cluster /status/apiServerURL)" \
    "https://api.${new_domain}:6443" "Infrastructure apiServerURL should use the new domain"
assert_eq "$(field /kubernetes.io/config.openshift.io/infrastructures/cluster /status/infrastructureName)" \
    "$new_infra" "Infrastructure infrastructureName should be the new infra ID"
assert_eq "$(field /kubernetes.io/config.openshift.io/ingresses/cluster /spec/domain)" "apps.${new_domain}" \
    "Ingress domain should be the new apps domain"
assert_etcd_has /openshift.io/routes/openshift-monitoring/thanos-querier "thanos-querier-openshift-monitoring.apps.${new_domain}" \
    "Route host should use the new apps domain"
assert_etcd_has /openshift.io/oauth/clients/openshift-browser-client "https://oauth-openshift.apps.${new_domain}/oauth/token/display" \
    "OAuthClient redirect URI should use the new apps domain"
assert_etcd_has /kubernetes.io/secrets/openshift-config-managed/router-certs "apps.${new_domain}" \
    "router-certs data key should be renamed to the new apps domain"
assert_etcd_has /kubernetes.io/configmaps/kube-system/cluster-config-v1 "baseDomain: ${new_base}" \
    "install-config baseDomain should be the new base domain"
assert_etcd_has /kubernetes.io/configmaps/kube-system/cluster-config-v1 "name: ${new_name}" \
    "install-config metadata.name should be the new cluster name"

assert_contains "$(cat "$kubeconfig")" "https://api-int.${new_domain}:6443" "on-disk kubeconfig server should use the new domain"
assert_not_contains "$(cat "$kubeconfig")" "$old_domain" "on-disk kubeconfig should not reference the old domain"
assert_eq "$(cat "$apiserver_url_env")" "KUBERNETES_SERVICE_HOST='api-int.${new_domain}'
KUBERNETES_SERVICE_PORT='6443'" "apiserver-url.env should point at the new api-int host"
