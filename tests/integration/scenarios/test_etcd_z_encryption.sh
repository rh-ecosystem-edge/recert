#!/usr/bin/env bash

set -euo pipefail

# End-to-end kube_encryption_config coverage. Setting `kube_encryption_config`
# AND enabling encryption on the cluster (APIServer spec.encryption.type) makes
# recert encrypt secrets on commit AND re-encrypt the *entire* shared etcd
# keyspace (`reencrypt_resources`) at the end of the run. That would poison any
# serial etcd scenario running after this one, so this scenario is named
# `test_etcd_z_*` to sort LAST among serial tests.

workdir=$(setup_test_workdir "etcd_z_encryption")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

setup_webhook_authenticator "$crypto_dir"

# The kube-apiserver encryption-config file drives BOTH the encrypt path
# (config.yaml `kube_encryption_config`) and the decrypt path
# (build_decryption_transformers() discovers **/encryption-config/encryption-config
# files under cluster_customization_dirs).
encryption_config_file="${crypto_dir}/kube-apiserver-pod-1/encryption-config/encryption-config"
mkdir -p "$(dirname "$encryption_config_file")"
cat > "$encryption_config_file" <<'EOF'
{
  "kind": "EncryptionConfiguration",
  "apiVersion": "apiserver.config.k8s.io/v1",
  "resources": [
    {
      "resources": [
        "secrets"
      ],
      "providers": [
        {
          "aesgcm": {
            "keys": [
              {
                "name": "1",
                "secret": "ERERERERERERERERERERERERERERERERERERERERERE="
              }
            ]
          }
        },
        {
          "identity": {}
        }
      ]
    }
  ]
}
EOF

# Trap cleanup before the first write to the shared etcd keys
trap 'etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/default/app-tls-enc >/dev/null 2>&1; etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /1 >/dev/null 2>&1; etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/openshift-apiserver/encryption-config >/dev/null 2>&1; etcdctl del --endpoints="${ETCD_ENDPOINT:-localhost:2379}" /kubernetes.io/secrets/openshift-oauth-apiserver/encryption-config >/dev/null 2>&1' EXIT

etcd_put_tls_secret "default" "app-tls-enc" \
    "${crypto_dir}/server.crt" "${crypto_dir}/server.key"

# A short etcd key (single segment, no k8s resource prefix). Scans only
# enumerate keys via prefix queries so it is never matched directly, but its
# presence is a regression guard for resource_from_key() which used to index
# segment [2] unconditionally and panicked on keys with fewer than 3 segments.
etcd_put_json "/1" '{"kind":"ConfigMap","metadata":{"name":"1"}}'

# is_encryption_enabled() is gated on the APIServer "cluster" resource
# (config.openshift.io/v1): without spec.encryption.type set to aescbc/aesgcm,
# no encrypt/decrypt transformers are built and everything is committed as
# plaintext JSON.
etcd_put_json "/kubernetes.io/config.openshift.io/apiservers/cluster" '{
  "apiVersion": "config.openshift.io/v1",
  "kind": "APIServer",
  "metadata": {"name": "cluster"},
  "spec": {"encryption": {"type": "aesgcm"}}
}'

# build_decryption_transformers() also merges the openshift/oauth apiserver
# encryption-config Secrets found in etcd and errors if they are missing, so
# seed both with the same config.
secret_bytes=$(python3 -c 'import json,sys; sys.stdout.write(json.dumps(list(open(sys.argv[1], "rb").read())))' "$encryption_config_file")
for ns in openshift-apiserver openshift-oauth-apiserver; do
    etcd_put_json "/kubernetes.io/secrets/${ns}/encryption-config" "{
  \"apiVersion\": \"v1\",
  \"kind\": \"Secret\",
  \"metadata\": {\"name\": \"encryption-config\", \"namespace\": \"${ns}\"},
  \"data\": {\"encryption-config\": ${secret_bytes}}
}"
done

# A single config is reused for both runs; the run-1 summary is snapshotted
# before run 2 rewrites it.
cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
crypto_dirs:
  - ${crypto_dir}
cluster_customization_dirs:
  - ${crypto_dir}
force_expire: true
kube_encryption_config: ${encryption_config_file}
summary_file: ${workdir}/summary.yaml
EOF

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "Regenerated all crypto objects" "should regenerate crypto"
assert_contains "$output" "Committing to actual etcd" "should persist etcd cache"
cp "${workdir}/summary.yaml" "${workdir}/summary-run1.yaml"

# The rewritten secret should be encrypted on commit (aesgcm prefix)
raw_val=$(etcd_get "/kubernetes.io/secrets/default/app-tls-enc")
assert_match "$raw_val" '^k8s:enc:aesgcm:v1:1:' "secret should be encrypted in etcd"

# Run recert again with the same config: reading back the now-encrypted secret
# (and the re-encrypted baseline) must succeed via prefix-based decryption.
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success > /dev/null

raw_val_after=$(etcd_get "/kubernetes.io/secrets/default/app-tls-enc")
assert_match "$raw_val_after" '^k8s:enc:aesgcm:v1:1:' "secret should stay encrypted across round-trip"

assert_summary_valid "${workdir}/summary-run1.yaml"
assert_summary_valid "${workdir}/summary.yaml"