#!/usr/bin/env bash
# proxy: '<http>|<https>|<no>|<status_http>|<status_https>|<status_no>'. The Proxy CR
# spec gets the spec values; everything derived from the effective proxy (Proxy status,
# operator observedConfigs, workload env vars, MachineConfig/on-disk proxy.env) gets
# the status values.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_proxy_rename")
custom_dir="${workdir}/custom"
mkdir -p "$custom_dir"
setup_webhook_authenticator "$custom_dir"
proxy_env_file="${workdir}/files/proxy.env"
mcdorig_file="${custom_dir}/etc/mco/proxy.env.mcdorig"
mkdir -p "$(dirname "$proxy_env_file")" "$(dirname "$mcdorig_file")"

proxy_key="/kubernetes.io/config.openshift.io/proxies/cluster"
osapi_key="/kubernetes.io/operator.openshift.io/openshiftapiservers/cluster"
kas_key="/kubernetes.io/operator.openshift.io/kubeapiservers/cluster"
kcm_key="/kubernetes.io/operator.openshift.io/kubecontrollermanagers/cluster"
storage_key="/kubernetes.io/operator.openshift.io/storages/cluster"
mc_key="/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/99-test-proxy"
deploy_key="/kubernetes.io/deployments/openshift-test/proxied"
pod_cm_key="/kubernetes.io/configmaps/openshift-kube-apiserver/kube-apiserver-pod-1"
inline_mc_key="/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/99-test-proxy-inline"

restore_baseline() {
    etcd_del "$proxy_key" "$kas_key" "$kcm_key" "$storage_key" "$mc_key" "$deploy_key" "$pod_cm_key" "$inline_mc_key"
    # seed_etcd.sh's OpenShiftAPIServer (no observedConfig).
    etcd_put_json "$osapi_key" '{
  "apiVersion": "operator.openshift.io/v1",
  "kind": "OpenShiftAPIServer",
  "metadata": {"name": "cluster"},
  "spec": {"logLevel": "Normal"}
}'
}
trap restore_baseline EXIT

seed_http="http://seed-proxy.example.com:3128"
seed_proxy_obj='{"HTTP_PROXY": "'"$seed_http"'", "HTTPS_PROXY": "'"$seed_http"'", "NO_PROXY": ".seed.example.com"}'

etcd_put_json "$proxy_key" '{
  "apiVersion": "config.openshift.io/v1",
  "kind": "Proxy",
  "metadata": {"name": "cluster"},
  "spec": {"httpProxy": "'"$seed_http"'", "httpsProxy": "'"$seed_http"'", "noProxy": ".seed.example.com", "trustedCA": {"name": ""}},
  "status": {"httpProxy": "'"$seed_http"'", "httpsProxy": "'"$seed_http"'", "noProxy": ".seed.example.com"}
}'
etcd_put_json "$osapi_key" '{
  "apiVersion": "operator.openshift.io/v1",
  "kind": "OpenShiftAPIServer",
  "metadata": {"name": "cluster"},
  "spec": {"logLevel": "Normal", "observedConfig": {"workloadcontroller": {"proxy": '"$seed_proxy_obj"'}}}
}'
for kind in KubeAPIServer KubeControllerManager; do
    key=$kas_key
    [[ "$kind" == KubeControllerManager ]] && key=$kcm_key
    etcd_put_json "$key" '{
  "apiVersion": "operator.openshift.io/v1",
  "kind": "'"$kind"'",
  "metadata": {"name": "cluster"},
  "spec": {"observedConfig": {"targetconfigcontroller": {"proxy": '"$seed_proxy_obj"'}}}
}'
done
etcd_put_json "$storage_key" '{
  "apiVersion": "operator.openshift.io/v1",
  "kind": "Storage",
  "metadata": {"name": "cluster"},
  "spec": {"observedConfig": {"targetconfig": {"proxy": '"$seed_proxy_obj"'}}}
}'
etcd_put_json "$deploy_key" '{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {"name": "proxied", "namespace": "openshift-test"},
  "spec": {
    "selector": {"matchLabels": {"app": "proxied"}},
    "template": {
      "metadata": {"labels": {"app": "proxied"}},
      "spec": {"containers": [{"name": "app", "image": "app:latest", "env": [
        {"name": "KEEP_ME", "value": "1"},
        {"name": "HTTP_PROXY", "value": "'"$seed_http"'"},
        {"name": "NO_PROXY", "value": ".seed.example.com"},
        {"name": "http_proxy", "value": "'"$seed_http"'"}
      ]}]}
    }
  }
}'
pod_json='{"apiVersion":"v1","kind":"Pod","metadata":{"name":"kube-apiserver"},"spec":{"containers":[{"name":"kube-apiserver","env":[{"name":"HTTPS_PROXY","value":"'"$seed_http"'"}]}]}}'
etcd_put_json "$pod_cm_key" "$(python3 -c '
import json, sys
print(json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "kube-apiserver-pod-1", "namespace": "openshift-kube-apiserver"},
                  "data": {"pod.yaml": sys.argv[1]}}))
' "$pod_json")"
seed_proxy_env=$(printf 'FOO=bar\nHTTP_PROXY=%s\nHTTPS_PROXY=%s\nNO_PROXY=.seed.example.com\n' "$seed_http" "$seed_http")
printf '%s\n' "$seed_proxy_env" | tee "$proxy_env_file" > "$mcdorig_file"
etcd_put_json "$mc_key" "$(machineconfig_json 99-test-proxy /etc/mco/proxy.env "$seed_proxy_env"$'\n')"

write_config() {
    cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${custom_dir}
cluster_customization_files:
  - ${proxy_env_file}
postprocess_only: true
proxy: '$1'
EOF
}

# 1. A malformed value (five parts) is rejected up front.
write_config "a|b|c|d|e"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "expected six parts separated by '|'" "five-part proxy value should be rejected"

# 2. A MachineConfig whose proxy.env file uses inline contents instead of source
#    (valid Ignition) must be a clean error, not a panic on the missing key.
etcd_put_json "$inline_mc_key" '{"apiVersion": "machineconfiguration.openshift.io/v1", "kind": "MachineConfig",
  "metadata": {"name": "99-test-proxy-inline"},
  "spec": {"config": {"storage": {"files": [{"path": "/etc/mco/proxy.env",
    "contents": {"compression": "", "inline": "Rk9PPWJhcgo="}}]}}}}'
write_config "http://a.example.com|https://b.example.com|.c.example.com|http://d.example.com|https://e.example.com|.f.example.com"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "source not found" "inline file contents without source should fail cleanly"
assert_not_contains "$output" "panicked" "a missing source key must not panic"
etcd_del "$inline_mc_key"

# 3. Full rename. The status https proxy is empty to check empty values drop env vars.
spec_http="http://spec-proxy.example.com:3128"
spec_https="https://spec-proxy.example.com:3129"
spec_no=".spec.example.com"
status_http="http://status-proxy.example.com:3128"
status_no=".status.example.com,10.0.0.0/16"
write_config "${spec_http}|${spec_https}|${spec_no}|${status_http}||${status_no}"
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null

proxy_fields() { etcd_json_pointer "$@"; }
assert_eq "$(proxy_fields "$proxy_key" /spec)" \
    '{"httpProxy": "'"$spec_http"'", "httpsProxy": "'"$spec_https"'", "noProxy": "'"$spec_no"'", "trustedCA": {"name": ""}}' \
    "Proxy spec should carry the spec values"
assert_eq "$(proxy_fields "$proxy_key" /status)" \
    '{"httpProxy": "'"$status_http"'", "httpsProxy": "", "noProxy": "'"$status_no"'"}' \
    "Proxy status should carry the status values"

expected_operator_proxy='{"HTTPS_PROXY": "", "HTTP_PROXY": "'"$status_http"'", "NO_PROXY": "'"$status_no"'"}'
assert_eq "$(proxy_fields "$osapi_key" /spec/observedConfig/workloadcontroller/proxy)" "$expected_operator_proxy" \
    "OpenShiftAPIServer workloadcontroller proxy should carry the status values"
assert_eq "$(proxy_fields "$kas_key" /spec/observedConfig/targetconfigcontroller/proxy)" "$expected_operator_proxy" \
    "KubeAPIServer targetconfigcontroller proxy should carry the status values"
assert_eq "$(proxy_fields "$kcm_key" /spec/observedConfig/targetconfigcontroller/proxy)" "$expected_operator_proxy" \
    "KubeControllerManager targetconfigcontroller proxy should carry the status values"
assert_eq "$(proxy_fields "$storage_key" /spec/observedConfig/targetconfig/proxy)" "$expected_operator_proxy" \
    "Storage targetconfig proxy should carry the status values"

expected_env="FOO=bar
HTTP_PROXY=${status_http}
NO_PROXY=${status_no}"
assert_eq "$(etcd_mc_file "$mc_key" /etc/mco/proxy.env)" "$expected_env" "MachineConfig proxy.env should carry the status values"
assert_eq "$(cat "$proxy_env_file")" "$expected_env" "proxy.env file should carry the status values"
assert_eq "$(cat "$mcdorig_file")" "$expected_env" "proxy.env.mcdorig should carry the status values"

# Workloads and static pod ConfigMaps are protobuf-encoded on commit.
assert_etcd_has "$deploy_key" "$status_http" "Deployment proxy env should carry the status http proxy"
assert_etcd_has "$deploy_key" "$status_no" "Deployment proxy env should carry the status no_proxy"
assert_etcd_has "$deploy_key" "KEEP_ME" "unrelated env vars must be kept"
assert_etcd_lacks "$deploy_key" "$seed_http" "Deployment should drop the seed proxy (both casings)"
assert_etcd_lacks "$pod_cm_key" "$seed_http" "kube-apiserver pod ConfigMap should drop the seed proxy"
assert_etcd_lacks "$pod_cm_key" "HTTPS_PROXY" "empty status https proxy should remove HTTPS_PROXY"
