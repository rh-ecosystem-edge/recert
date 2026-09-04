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
  # spiffe URIs contain ':' (scheme), so use the comma separator that CnSanReplace
  # also accepts (the IPv6 escape hatch) instead of the default ':' split.
  - "spiffe://old-cluster.example.com/ns/default/sa/app,spiffe://new-cluster.example.com/ns/default/sa/app"
  - "admin@old-cluster.example.com:admin@new-cluster.example.com"
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
assert_contains "$output" "Updating cert-manager Certificate ipAddress" \
    "should rename ipAddresses"
assert_contains "$output" "Updating cert-manager Certificate uri" \
    "should rename uris"
assert_contains "$output" "Updating cert-manager Certificate emailAddress" \
    "should rename emailAddresses"
assert_contains "$output" "Deleting stale cert-manager CertificateRequest" \
    "should clean up stale CertificateRequests"

cm_after=$(etcd_get "/kubernetes.io/cert-manager.io/certificates/default/app-tls")
assert_contains "$cm_after" '"commonName":"new-cluster.example.com"' \
    "etcd Certificate commonName should be rewritten"
assert_contains "$cm_after" "api.new-cluster.example.com" \
    "etcd Certificate dnsNames should be rewritten"
assert_not_contains "$cm_after" '"commonName":"old-cluster.example.com"' \
    "etcd Certificate commonName should not keep the old domain"
assert_contains "$cm_after" '"ipAddresses":["10.0.0.50"]' \
    "ipAddresses matching a rule should be rewritten"
assert_contains "$cm_after" '"uris":["spiffe://new-cluster.example.com/ns/default/sa/app"]' \
    "uris matching a rule should be rewritten"
assert_contains "$cm_after" '"emailAddresses":["admin@new-cluster.example.com"]' \
    "emailAddresses matching a rule should be rewritten"
assert_not_contains "$cm_after" "spiffe://old-cluster.example.com" \
    "uris should not keep the old spiffe value"
assert_not_contains "$cm_after" "admin@old-cluster.example.com" \
    "emailAddresses should not keep the old address"

cr_after=$(etcd_get "/kubernetes.io/cert-manager.io/certificaterequests/default/app-tls-old-req")
assert_eq "$cr_after" "" "stale CertificateRequest should be deleted from etcd"
