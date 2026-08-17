#!/usr/bin/env bash

set -euo pipefail

workdir=$(setup_test_workdir "etcd_cert_manager")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key server.crt server.key)

setup_webhook_authenticator "$crypto_dir"

etcd_put_json "/kubernetes.io/cert-manager.io/certificates/default/app-tls" '{
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
etcd_put_json "/kubernetes.io/cert-manager.io/certificaterequests/default/app-tls-old-req" '{
  "apiVersion": "cert-manager.io/v1",
  "kind": "CertificateRequest",
  "metadata": {"name": "app-tls-old-req", "namespace": "default"},
  "spec": {"issuerRef": {"name": "cluster-issuer", "kind": "ClusterIssuer"}}
}'

precheck_cert "${crypto_dir}/ca.crt"
precheck_cert "${crypto_dir}/server.crt"
cm_data=$(precheck_etcd_key "/kubernetes.io/cert-manager.io/certificates/default/app-tls" "cert-manager CRD seeded")
precheck_etcd_key "/kubernetes.io/cert-manager.io/certificaterequests/default/app-tls-old-req" "stale CR seeded" >/dev/null
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

output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success)
assert_contains "$output" "Checking 1 cert-manager Certificate CRs" \
    "should detect cert-manager certificates"
assert_contains "$output" "Updating cert-manager Certificate commonName" \
    "should rename commonName"
assert_contains "$output" "Updating cert-manager Certificate dnsName" \
    "should rename dnsNames"
assert_contains "$output" "Deleting stale cert-manager CertificateRequest" \
    "should clean up stale CertificateRequests"

cm_after=$(etcd_get "/kubernetes.io/cert-manager.io/certificates/default/app-tls")
assert_contains "$cm_after" '"commonName":"new-cluster.example.com"' \
    "etcd Certificate commonName should be rewritten"
assert_contains "$cm_after" "api.new-cluster.example.com" \
    "etcd Certificate dnsNames should be rewritten"
assert_not_contains "$cm_after" '"commonName":"old-cluster.example.com"' \
    "etcd Certificate commonName should not keep the old domain"
# Main only rewrites commonName/dnsNames — IP/URI/email stay as-is
assert_contains "$cm_after" '"ipAddresses":["192.168.1.100"]' \
    "ipAddresses should be unchanged on main"
assert_contains "$cm_after" "spiffe://old-cluster.example.com/ns/default/sa/app" \
    "uris should be unchanged on main"
assert_contains "$cm_after" "admin@old-cluster.example.com" \
    "emailAddresses should be unchanged on main"

cr_after=$(etcd_get "/kubernetes.io/cert-manager.io/certificaterequests/default/app-tls-old-req")
assert_eq "$cr_after" "" "stale CertificateRequest should be deleted from etcd"
