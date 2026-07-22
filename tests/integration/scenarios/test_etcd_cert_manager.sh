#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_cert_manager")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

# Create webhook-authenticator structure that ocp_postprocess expects
mkdir -p "${crypto_dir}/kube-apiserver-pod-1/webhook-authenticator"
cat > "${crypto_dir}/kube-apiserver-pod-1/webhook-authenticator/kubeConfig" <<'KUBECONFIG'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: local
KUBECONFIG

etcdctl put --endpoints=localhost:2379 \
    "/kubernetes.io/secrets/openshift-kube-apiserver/webhook-authenticator-1" \
    '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"webhook-authenticator-1","namespace":"openshift-kube-apiserver"},"data":{}}'
etcdctl put --endpoints=localhost:2379 \
    "/kubernetes.io/secrets/openshift-kube-apiserver/webhook-authenticator" \
    '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"webhook-authenticator","namespace":"openshift-kube-apiserver"},"data":{}}'
etcdctl put --endpoints=localhost:2379 \
    "/kubernetes.io/secrets/openshift-config/webhook-authentication-integrated-oauth" \
    '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"webhook-authentication-integrated-oauth","namespace":"openshift-config"},"data":{}}'

# Seed cert-manager Certificate CRDs with all SAN-related spec fields
etcdctl put --endpoints=localhost:2379 \
    "/kubernetes.io/cert-manager.io/certificates/default/app-tls" \
    '{
      "apiVersion": "cert-manager.io/v1",
      "kind": "Certificate",
      "metadata": {"name": "app-tls", "namespace": "default"},
      "spec": {
        "commonName": "old-cluster.example.com",
        "dnsNames": ["old-cluster.example.com", "api.old-cluster.example.com"],
        "ipAddresses": ["192.168.1.100"],
        "uris": ["spiffe://old-cluster.example.com/ns/default/sa/app"],
        "emailAddresses": ["admin@old-cluster.example.com"],
        "secretName": "app-tls-secret",
        "issuerRef": {"name": "cluster-issuer", "kind": "ClusterIssuer"}
      }
    }'

# Seed a stale CertificateRequest (should be deleted by recert)
etcdctl put --endpoints=localhost:2379 \
    "/kubernetes.io/cert-manager.io/certificaterequests/default/app-tls-old-req" \
    '{
      "apiVersion": "cert-manager.io/v1",
      "kind": "CertificateRequest",
      "metadata": {"name": "app-tls-old-req", "namespace": "default"},
      "spec": {"issuerRef": {"name": "cluster-issuer", "kind": "ClusterIssuer"}}
    }'

# Prechecks — validate setup before slow recert invocation
precheck_cert "${crypto_dir}/ca.crt"
precheck_cert "${crypto_dir}/server.crt"
precheck_etcd_key "/kubernetes.io/cert-manager.io/certificates/default/app-tls" "cert-manager CRD seeded"
precheck_etcd_key "/kubernetes.io/cert-manager.io/certificaterequests/default/app-tls-old-req" "stale CR seeded"
cm_data=$(etcdctl get --endpoints=localhost:2379 "/kubernetes.io/cert-manager.io/certificates/default/app-tls" --print-value-only)
assert_contains "$cm_data" "old-cluster.example.com" "precheck: CRD has old domain before recert"

cat > "${workdir}/config.yaml" <<EOF
etcd_endpoint: localhost:2379
crypto_dirs:
  - ${crypto_dir}
cluster_customization_dirs:
  - ${crypto_dir}
cn_san_replace_rules:
  - "old-cluster.example.com:new-cluster.example.com"
  - "api.old-cluster.example.com:api.new-cluster.example.com"
  - "192.168.1.100:10.0.0.50"
force_expire: true
summary_file: ${workdir}/summary.yaml
EOF

# ocp_postprocess runs cert-manager rename early in the pipeline, but
# may fail later on missing OCP operator resources. We verify from log
# output that cert-manager processing ran correctly. The rename logic
# itself is covered by 11 Rust unit tests in cert_manager_rename.rs.
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "Checking 1 cert-manager Certificate CRs" \
    "should detect cert-manager certificates"
assert_contains "$output" "Updating cert-manager Certificate commonName" \
    "should rename commonName"
assert_contains "$output" "Updating cert-manager Certificate dnsName" \
    "should rename dnsNames"
assert_contains "$output" "Deleting stale cert-manager CertificateRequest" \
    "should clean up stale CertificateRequests"
