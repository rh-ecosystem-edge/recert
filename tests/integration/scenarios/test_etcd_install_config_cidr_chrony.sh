#!/usr/bin/env bash
# install_config, machine_network_cidr and chrony_config: the small text-replacement
# customizations. Pins that machine_network_cidr runs after install_config (so it wins
# for networking.machineNetwork) and that a cluster-config-v1 ConfigMap without an
# install-config key is a clean error rather than a panic.

set -euo pipefail

workdir=$(setup_test_workdir "etcd_install_config_cidr_chrony")
custom_dir="${workdir}/custom"
mkdir -p "$custom_dir"
setup_webhook_authenticator "$custom_dir"
chrony_file="${workdir}/files/chrony.conf"
mkdir -p "$(dirname "$chrony_file")"

cm_keys=(
    "/kubernetes.io/configmaps/kube-system/cluster-config-v1"
    "/kubernetes.io/configmaps/openshift-etcd/cluster-config-v1"
)
mc_key="/kubernetes.io/machineconfiguration.openshift.io/machineconfigs/99-test-chrony"
trap 'etcd_del "${cm_keys[@]}" "$mc_key"' EXIT

install_config_yaml() {
    local marker="$1" cidr="$2"
    cat <<EOF
apiVersion: v1
baseDomain: ${marker}.example.com
metadata:
  name: sno
networking:
  machineNetwork:
  - cidr: ${cidr}
EOF
}

seed_cluster_config() {
    local data_json="$1" key ns
    for key in "${cm_keys[@]}"; do
        ns=$(cut -d/ -f4 <<<"$key")
        etcd_put_json "$key" '{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {"name": "cluster-config-v1", "namespace": "'"$ns"'"},
  "data": '"$data_json"'
}'
    done
}

seed_cluster_config "$(install_config_yaml seed 192.168.1.0/24 | python3 -c 'import json,sys; print(json.dumps({"install-config": sys.stdin.read()}))')"
etcd_put_json "$mc_key" "$(machineconfig_json 99-test-chrony /etc/chrony.conf "server seed-ntp.example.com iburst")"
printf 'server seed-ntp.example.com iburst\n' > "$chrony_file"

run_with() {
    cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
cluster_customization_dirs:
  - ${custom_dir}
cluster_customization_files:
  - ${chrony_file}
postprocess_only: true
$1
EOF
    RECERT_CONFIG="${workdir}/config.yaml" "$2"
}

# 1. machine_network_cidr alone replaces networking.machineNetwork in both ConfigMaps.
run_with "machine_network_cidr: 10.1.0.0/24" run_recert_expect_success >/dev/null
for key in "${cm_keys[@]}"; do
    assert_etcd_has "$key" "10.1.0.0/24" "${key}: machineNetwork should be the new CIDR"
    assert_etcd_lacks "$key" "192.168.1.0/24" "${key}: seed machineNetwork should be gone"
    assert_etcd_has "$key" "seed.example.com" "${key}: the rest of install-config should be kept"
done

# 2. install_config replaces the whole document, then machine_network_cidr (which runs
#    after it) overrides the machineNetwork that install_config carried.
new_install_config=$(install_config_yaml replaced 10.2.0.0/24 | sed 's/^/  /')
run_with "install_config: |
${new_install_config}
machine_network_cidr: 10.3.0.0/24" run_recert_expect_success >/dev/null
for key in "${cm_keys[@]}"; do
    assert_etcd_has "$key" "replaced.example.com" "${key}: install_config should replace the document"
    assert_etcd_lacks "$key" "seed.example.com" "${key}: old install-config should be gone"
    assert_etcd_has "$key" "10.3.0.0/24" "${key}: machine_network_cidr should win over install_config's CIDR"
    assert_etcd_lacks "$key" "10.2.0.0/24" "${key}: install_config's machineNetwork should be overridden"
done

# 3. chrony_config rewrites the MachineConfig /etc/chrony.conf and the chrony.conf file.
new_chrony="server ntp.new.example.com iburst"
run_with "chrony_config: '${new_chrony}'" run_recert_expect_success >/dev/null
assert_eq "$(etcd_mc_file "$mc_key" /etc/chrony.conf)" "$new_chrony" "MachineConfig chrony.conf should be replaced"
assert_eq "$(cat "$chrony_file")" "$new_chrony" "on-disk chrony.conf should be replaced"

# 4. A cluster-config-v1 without install-config is an error, not a panic.
seed_cluster_config '{"unrelated": "value"}'
output=$(run_with "machine_network_cidr: 10.4.0.0/24" run_recert_expect_failure)
assert_contains "$output" "install-config not found" "missing install-config should be a clean error"
assert_not_contains "$output" "panicked" "missing install-config must not panic"
