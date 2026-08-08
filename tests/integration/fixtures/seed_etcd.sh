#!/usr/bin/env bash

set -euo pipefail

ETCD_ENDPOINT="${1:-localhost:2379}"

put() {
    etcdctl put --endpoints="$ETCD_ENDPOINT" "$1" "$2"
}

DUMMY_CA_BUNDLE=$(echo "dummy-ca-data" | base64)

# ── Required by is_encryption_enabled() ──
put "/kubernetes.io/config.openshift.io/apiservers/cluster" '{
  "apiVersion": "config.openshift.io/v1",
  "kind": "APIServer",
  "metadata": {"name": "cluster"},
  "spec": {}
}'

# ── Required by discover_external_certs() ──
put "/kubernetes.io/configmaps/openshift-config-managed/trusted-ca-bundle" '{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {"name": "trusted-ca-bundle", "namespace": "openshift-config-managed"},
  "data": {"ca-bundle.crt": ""}
}'

put "/kubernetes.io/config.openshift.io/images/cluster" '{
  "apiVersion": "config.openshift.io/v1",
  "kind": "Image",
  "metadata": {"name": "cluster"},
  "spec": {}
}'

# ── Required by fix_olm_secret_hash_annotation() ──
put "/kubernetes.io/apiregistration.k8s.io/apiservices/v1.packages.operators.coreos.com" "{
  \"apiVersion\": \"apiregistration.k8s.io/v1\",
  \"kind\": \"APIService\",
  \"metadata\": {\"name\": \"v1.packages.operators.coreos.com\"},
  \"spec\": {\"caBundle\": \"${DUMMY_CA_BUNDLE}\"}
}"

put "/kubernetes.io/secrets/openshift-operator-lifecycle-manager/packageserver-service-cert" '{
  "apiVersion": "v1",
  "kind": "Secret",
  "metadata": {
    "name": "packageserver-service-cert",
    "namespace": "openshift-operator-lifecycle-manager",
    "annotations": {}
  },
  "data": {}
}'

# ── Required by set_cluster_version_available_false() ──
put "/kubernetes.io/config.openshift.io/clusterversions/version" '{
  "apiVersion": "config.openshift.io/v1",
  "kind": "ClusterVersion",
  "metadata": {"name": "version"},
  "status": {
    "conditions": [
      {"type": "Available", "status": "True"}
    ]
  }
}'

# ── Required by fix_deployment_spec_hash_annotation() ──
put "/kubernetes.io/operator.openshift.io/openshiftapiservers/cluster" '{
  "apiVersion": "operator.openshift.io/v1",
  "kind": "OpenShiftAPIServer",
  "metadata": {"name": "cluster"},
  "spec": {"logLevel": "Normal"}
}'

put "/kubernetes.io/deployments/openshift-apiserver-operator/openshift-apiserver-operator" '{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {"name": "openshift-apiserver-operator", "namespace": "openshift-apiserver-operator"},
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "openshift-apiserver-operator",
          "env": [{"name": "KUBE_APISERVER_OPERATOR_IMAGE", "value": "dummy-image:latest"}]
        }]
      }
    }
  }
}'

# ── Resources referenced by deployment dep-annotations ──
for name in config audit-1; do
  put "/kubernetes.io/configmaps/openshift-apiserver/${name}" "{
    \"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",
    \"metadata\":{\"name\":\"${name}\",\"namespace\":\"openshift-apiserver\"},
    \"data\":{}
  }"
done

for name in etcd-client serving-cert; do
  put "/kubernetes.io/secrets/openshift-apiserver/${name}" "{
    \"apiVersion\":\"v1\",\"kind\":\"Secret\",
    \"metadata\":{\"name\":\"${name}\",\"namespace\":\"openshift-apiserver\"},
    \"data\":{}
  }"
done

for name in etcd-serving-ca image-import-ca trusted-ca-bundle; do
  put "/kubernetes.io/configmaps/openshift-apiserver/${name}" "{
    \"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",
    \"metadata\":{\"name\":\"${name}\",\"namespace\":\"openshift-apiserver\"},
    \"data\":{}
  }"
done

for name in etcd-client; do
  put "/kubernetes.io/secrets/openshift-oauth-apiserver/${name}" "{
    \"apiVersion\":\"v1\",\"kind\":\"Secret\",
    \"metadata\":{\"name\":\"${name}\",\"namespace\":\"openshift-oauth-apiserver\"},
    \"data\":{}
  }"
done

for name in etcd-serving-ca; do
  put "/kubernetes.io/configmaps/openshift-oauth-apiserver/${name}" "{
    \"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",
    \"metadata\":{\"name\":\"${name}\",\"namespace\":\"openshift-oauth-apiserver\"},
    \"data\":{}
  }"
done

# ── Deployments with full structure for dep/spec-hash annotation fixes ──
APISERVER_ANNOTATIONS='"openshiftapiservers.operator.openshift.io/pull-spec":"dummy","operator.openshift.io/dep-desired.generation":"1","operator.openshift.io/dep-openshift-apiserver.config.configmap":"hash","operator.openshift.io/dep-openshift-apiserver.etcd-client.secret":"hash","operator.openshift.io/dep-openshift-apiserver.etcd-serving-ca.configmap":"hash","operator.openshift.io/dep-openshift-apiserver.image-import-ca.configmap":"hash","operator.openshift.io/dep-openshift-apiserver.trusted-ca-bundle.configmap":"hash"'

put "/kubernetes.io/deployments/openshift-apiserver/apiserver" "{
  \"apiVersion\": \"v1\",
  \"kind\": \"Deployment\",
  \"metadata\": {
    \"name\": \"apiserver\",
    \"namespace\": \"openshift-apiserver\",
    \"labels\": {\"revision\": \"1\"},
    \"annotations\": {${APISERVER_ANNOTATIONS}}
  },
  \"spec\": {
    \"template\": {
      \"metadata\": {\"annotations\": {${APISERVER_ANNOTATIONS}}}
    }
  }
}"

# ── Required by fix_deployment_spec_hash_annotation (oauth-apiserver) ──
put "/kubernetes.io/operator.openshift.io/authentications/cluster" '{
  "apiVersion": "operator.openshift.io/v1",
  "kind": "Authentication",
  "metadata": {"name": "cluster"},
  "spec": {
    "logLevel": "Normal",
    "observedConfig": {
      "oauthAPIServer": {
        "apiServerArguments": {}
      }
    }
  }
}'

OAUTH_ANNOTATIONS='"operator.openshift.io/dep-openshift-oauth-apiserver.etcd-client.secret":"hash","operator.openshift.io/dep-openshift-oauth-apiserver.etcd-serving-ca.configmap":"hash"'

put "/kubernetes.io/deployments/openshift-oauth-apiserver/apiserver" "{
  \"apiVersion\": \"v1\",
  \"kind\": \"Deployment\",
  \"metadata\": {
    \"name\": \"apiserver\",
    \"namespace\": \"openshift-oauth-apiserver\",
    \"labels\": {\"revision\": \"1\"},
    \"annotations\": {${OAUTH_ANNOTATIONS}}
  },
  \"spec\": {
    \"template\": {
      \"metadata\": {\"annotations\": {${OAUTH_ANNOTATIONS}}},
      \"spec\": {
        \"containers\": [{
          \"name\": \"oauth-apiserver\",
          \"image\": \"dummy-oauth-image:latest\"
        }]
      }
    }
  }
}"

echo "etcd seeded with minimal OCP resources"
