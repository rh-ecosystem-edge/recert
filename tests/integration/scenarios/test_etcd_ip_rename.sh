#!/usr/bin/env bash
# ip: the node's InternalIP(s) are replaced in the etcd static pod and scripts, etcd
# endpoints/secrets, kube-apiserver/openshift-apiserver/oauth-apiserver etcd-servers,
# the OVN initiator annotation and on-disk static pod files. Single-stack takes one IP,
# dual-stack two (IPv4 first); runtime objects (nodes, pods) are deleted.
#
# Several required objects are seed_etcd.sh baseline objects; the baseline is re-seeded
# on exit.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_ip_rename")
custom_dir="${workdir}/custom"
mkdir -p "$custom_dir"
setup_webhook_authenticator "$custom_dir"

node_key="/kubernetes.io/minions/sno"
pod_key="/kubernetes.io/pods/openshift-etcd/etcd-sno"
osapi_config_key="/kubernetes.io/configmaps/openshift-apiserver/config"
endpoints_key="/kubernetes.io/configmaps/openshift-etcd/etcd-endpoints"
etcd_pod_key="/kubernetes.io/configmaps/openshift-etcd/etcd-pod-2"
scripts_key="/kubernetes.io/configmaps/openshift-etcd/etcd-scripts"
peer_secret_key="/kubernetes.io/secrets/openshift-etcd/etcd-peer-sno"
kas_config_key="/kubernetes.io/configmaps/openshift-kube-apiserver/config"
kas_key="/kubernetes.io/operator.openshift.io/kubeapiservers/cluster"
auth_key="/kubernetes.io/operator.openshift.io/authentications/cluster"
osapi_key="/kubernetes.io/operator.openshift.io/openshiftapiservers/cluster"
network_key="/kubernetes.io/operator.openshift.io/networks/cluster"
oauth_deploy_key="/kubernetes.io/deployments/openshift-oauth-apiserver/apiserver"
malformed_kas_key="/kubernetes.io/configmaps/openshift-kube-apiserver/config-malformed"
fs_etcd_pod="${custom_dir}/static-pod-resources/etcd-pod-2/etcd-pod.yaml"
fs_kas_config="${custom_dir}/kube-apiserver-pod-1/configmaps/config/config.yaml"

restore_baseline() {
    etcd_del "$node_key" "$pod_key" "$endpoints_key" "$etcd_pod_key" "$scripts_key" "$peer_secret_key" \
        "$kas_config_key" "$kas_key" "$network_key" "$malformed_kas_key"
    bash "${INTEGRATION_LIB_DIR}/../fixtures/seed_etcd.sh" >/dev/null
}
trap restore_baseline EXIT

json_str() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
url_host() { if [[ "$1" == *:* ]]; then echo "[$1]"; else echo "$1"; fi; }

# seed_ip_fixtures IPV4 [IPV6]
seed_ip_fixtures() {
    local v4="$1" v6="${2:-}"
    local addresses='{"type": "InternalIP", "address": "'"$v4"'"}'
    local etcd_servers='"https://'"$v4"':2379", "https://localhost:2379"'
    local pod_yaml="ETCDCTL_ENDPOINTS=https://${v4}:2379 --listen-peer-urls=https://${v4}:2380"
    local etcd_env="export ALL_ETCD_ENDPOINTS=\"https://${v4}:2379\"
export NODE_sno_ETCD_URL_HOST=\"${v4}\"
export NODE_sno_IP=\"${v4}\""
    if [[ -n "$v6" ]]; then
        addresses+=', {"type": "InternalIP", "address": "'"$v6"'"}'
        etcd_servers+=', "https://['"$v6"']:2379"'
        pod_yaml+=" --listen-client-urls=https://[${v6}]:2379"
        etcd_env+="
export NODE_sno_IPV6_IP=\"[${v6}]\""
    fi
    addresses+=', {"type": "Hostname", "address": "sno"}'

    etcd_put_json "$node_key" '{"apiVersion": "v1", "kind": "Node", "metadata": {"name": "sno"},
      "status": {"addresses": ['"$addresses"']}}'
    etcd_put_json "$pod_key" '{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "etcd-sno", "namespace": "openshift-etcd"},
      "spec": {"containers": [{"name": "etcd", "image": "etcd:latest"}]}}'
    etcd_put_json "$osapi_config_key" '{"apiVersion": "v1", "kind": "ConfigMap",
      "metadata": {"name": "config", "namespace": "openshift-apiserver"},
      "data": {"config.yaml": '"$(json_str '{"storageConfig": {"urls": ["https://'"$v4"':2379"]}}')"'}}'
    etcd_put_json "$endpoints_key" '{"apiVersion": "v1", "kind": "ConfigMap",
      "metadata": {"name": "etcd-endpoints", "namespace": "openshift-etcd"}, "data": {"5f4e3d2c1b0a": "'"$v4"'"}}'
    etcd_put_json "$etcd_pod_key" '{"apiVersion": "v1", "kind": "ConfigMap",
      "metadata": {"name": "etcd-pod-2", "namespace": "openshift-etcd"}, "data": {"pod.yaml": '"$(json_str "$pod_yaml")"'}}'
    etcd_put_json "$scripts_key" '{"apiVersion": "v1", "kind": "ConfigMap",
      "metadata": {"name": "etcd-scripts", "namespace": "openshift-etcd"}, "data": {"etcd.env": '"$(json_str "$etcd_env")"'}}'
    etcd_put_json "$peer_secret_key" '{"apiVersion": "v1", "kind": "Secret",
      "metadata": {"name": "etcd-peer-sno", "namespace": "openshift-etcd",
                   "annotations": {"auth.openshift.io/certificate-hostnames": "localhost,'"$v4"'"}}, "data": {}}'
    etcd_put_json "$kas_config_key" '{"apiVersion": "v1", "kind": "ConfigMap",
      "metadata": {"name": "config", "namespace": "openshift-kube-apiserver"},
      "data": {"config.yaml": '"$(json_str '{"apiServerArguments": {"etcd-servers": ['"$etcd_servers"']}}')"'}}'
    etcd_put_json "$kas_key" '{"apiVersion": "operator.openshift.io/v1", "kind": "KubeAPIServer", "metadata": {"name": "cluster"},
      "spec": {"observedConfig": {"apiServerArguments": {"etcd-servers": ['"$etcd_servers"']}}}}'
    etcd_put_json "$auth_key" '{"apiVersion": "operator.openshift.io/v1", "kind": "Authentication", "metadata": {"name": "cluster"},
      "spec": {"logLevel": "Normal", "observedConfig": {"oauthAPIServer": {"apiServerArguments": {"etcd-servers": ['"$etcd_servers"']}}}}}'
    etcd_put_json "$osapi_key" '{"apiVersion": "operator.openshift.io/v1", "kind": "OpenShiftAPIServer", "metadata": {"name": "cluster"},
      "spec": {"logLevel": "Normal", "observedConfig": {"storageConfig": {"urls": ["https://'"$v4"':2379"]}}}}'
    etcd_put_json "$network_key" '{"apiVersion": "operator.openshift.io/v1", "kind": "Network",
      "metadata": {"name": "cluster", "annotations": {"networkoperator.openshift.io/ovn-cluster-initiator": "'"$v4"'"}}}'
    local oauth_annotations='"operator.openshift.io/dep-openshift-oauth-apiserver.etcd-client.secret":"hash","operator.openshift.io/dep-openshift-oauth-apiserver.etcd-serving-ca.configmap":"hash"'
    etcd_put_json "$oauth_deploy_key" '{"apiVersion": "apps/v1", "kind": "Deployment",
      "metadata": {"name": "apiserver", "namespace": "openshift-oauth-apiserver", "labels": {"revision": "1"}, "annotations": {'"$oauth_annotations"'}},
      "spec": {"selector": {"matchLabels": {"app": "openshift-oauth-apiserver"}},
        "template": {"metadata": {"labels": {"app": "openshift-oauth-apiserver"}, "annotations": {'"$oauth_annotations"'}},
          "spec": {"containers": [{"name": "oauth-apiserver", "image": "dummy-oauth-image:latest",
            "args": ["--etcd-servers=https://'"$v4"':2379", "--v=2"]}]}}}}'

    mkdir -p "$(dirname "$fs_etcd_pod")" "$(dirname "$fs_kas_config")"
    printf '%s\n' "$pod_yaml" > "$fs_etcd_pod"
    printf '{"apiServerArguments": {"etcd-servers": [%s]}}\n' "$etcd_servers" > "$fs_kas_config"
}

run_ip() {
    cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${custom_dir}
postprocess_only: true
ip: $1
EOF
    RECERT_CONFIG="${workdir}/config.yaml" "$2"
}

# assert_ip_renamed OLD NEW KEY...: OLD is gone and NEW is present in each etcd KEY and
# in the on-disk static pod files.
assert_ip_renamed() {
    local old="$1" new="$2" key
    shift 2
    for key in "$@"; do
        assert_etcd_has "$key" "$(url_host "$new")" "${key}: should reference ${new}"
        assert_etcd_lacks "$key" "$(url_host "$old")" "${key}: should not reference ${old}"
    done
    assert_contains "$(cat "$fs_etcd_pod")" "$(url_host "$new")" "on-disk etcd pod should reference ${new}"
    assert_not_contains "$(cat "$fs_etcd_pod")" "$(url_host "$old")" "on-disk etcd pod should not reference ${old}"
    assert_contains "$(cat "$fs_kas_config")" "$(url_host "$new")" "on-disk kube-apiserver config should reference ${new}"
    assert_not_contains "$(cat "$fs_kas_config")" "$(url_host "$old")" "on-disk kube-apiserver config should not reference ${old}"
}

# Objects seeded with both families vs. only IPv4 (openshift-apiserver storageConfig).
dual_stack_keys=("$etcd_pod_key" "$scripts_key" "$kas_config_key" "$kas_key" "$auth_key")
v4_only_keys=("$osapi_config_key")

old_v4="192.168.126.10"
new_v4="192.168.127.20"
old_v6="fd00:1101::10"
new_v6="fd00:1102::20"

# 1. Single-stack.
seed_ip_fixtures "$old_v4"
output=$(run_ip "$new_v4" run_recert_expect_success)
assert_contains "$output" "Found single-stack IP: ${old_v4}" "original IP should come from the node InternalIP"
assert_ip_renamed "$old_v4" "$new_v4" "${v4_only_keys[@]}" "${dual_stack_keys[@]}"
for key in "$endpoints_key" "$peer_secret_key" "$osapi_key" "$network_key" "$oauth_deploy_key"; do
    assert_etcd_has "$key" "$new_v4" "${key}: should reference ${new_v4}"
    assert_etcd_lacks "$key" "$old_v4" "${key}: should not reference ${old_v4}"
done
assert_etcd_has "$kas_key" "https://localhost:2379" "unrelated etcd-servers entries must be kept"
assert_etcd_absent "$node_key" "Node should be deleted so it is re-registered with the new IP"
assert_etcd_absent "$pod_key" "Pods should be deleted after an IP change"

# 2. Dual-stack: each family's IP is replaced in its own pass.
restore_baseline
seed_ip_fixtures "$old_v4" "$old_v6"
output=$(run_ip "['${new_v4}', '${new_v6}']" run_recert_expect_success)
assert_contains "$output" "Applying dual-stack IP changes" "two IPs should take the dual-stack path"
assert_ip_renamed "$old_v4" "$new_v4" "${v4_only_keys[@]}" "${dual_stack_keys[@]}"
assert_ip_renamed "$old_v6" "$new_v6" "${dual_stack_keys[@]}"

# 3. The number of IPs must match the node's InternalIPs.
restore_baseline
seed_ip_fixtures "$old_v4" "$old_v6"
output=$(run_ip "$new_v4" run_recert_expect_failure)
assert_contains "$output" "Expected single-stack (1 IP) but found 2 IPs" "a single IP for a dual-stack node should be rejected"

# 4. A longer address that has the old IP as a prefix must not be rewritten, in
#    either the etcd static pod, the on-disk static pod, or a host list annotation.
restore_baseline
seed_ip_fixtures "$old_v4"
decoy_v4="${old_v4}0" # 192.168.126.100
etcd_put_json "$etcd_pod_key" '{"apiVersion": "v1", "kind": "ConfigMap",
  "metadata": {"name": "etcd-pod-2", "namespace": "openshift-etcd"},
  "data": {"pod.yaml": '"$(json_str "ETCDCTL_ENDPOINTS=https://${old_v4}:2379 decoy=https://${decoy_v4}:2380")"'}}'
printf 'ETCDCTL_ENDPOINTS=https://%s:2379 decoy=https://%s:2380\n' "$old_v4" "$decoy_v4" > "$fs_etcd_pod"
etcd_put_json "$peer_secret_key" '{"apiVersion": "v1", "kind": "Secret",
  "metadata": {"name": "etcd-peer-sno", "namespace": "openshift-etcd",
               "annotations": {"auth.openshift.io/certificate-hostnames": "'"localhost,${decoy_v4},${old_v4}"'"}}, "data": {}}'
run_ip "$new_v4" run_recert_expect_success >/dev/null
assert_etcd_has "$etcd_pod_key" "https://${new_v4}:2379" "the node IP should still be rewritten"
assert_etcd_has "$etcd_pod_key" "https://${decoy_v4}:2380" "a longer address must be kept"
assert_etcd_lacks "$etcd_pod_key" "https://${old_v4}:2379" "the old address must be rewritten"
assert_contains "$(cat "$fs_etcd_pod")" "https://${decoy_v4}:2380" "on-disk static pod: a longer address must be kept"
assert_not_contains "$(cat "$fs_etcd_pod")" "https://${old_v4}:2379" "on-disk static pod: the old address must be rewritten"
assert_etcd_has "$peer_secret_key" "localhost,${decoy_v4},${new_v4}" \
    "only the exact host list entry should be replaced"

# 5. A kube-apiserver config ConfigMap without config.yaml must be a clean error.
restore_baseline
seed_ip_fixtures "$old_v4"
etcd_put_json "$malformed_kas_key" '{"apiVersion": "v1", "kind": "ConfigMap",
  "metadata": {"name": "config-malformed", "namespace": "openshift-kube-apiserver"},
  "data": {"other.yaml": "foo: bar"}}'
output=$(run_ip "$new_v4" run_recert_expect_failure)
assert_contains "$output" "config.yaml not found" "a kube-apiserver configmap without config.yaml should fail cleanly"
assert_not_contains "$output" "panicked" "a missing config.yaml key must not panic"
