#!/usr/bin/env python3
"""Minimal etcd objects that cluster_rename (cluster_domain_rename) requires.

Usage: cluster_rename_fixtures.py CLUSTER_NAME BASE_DOMAIN INFRA_ID
Prints one "<etcd key>\\t<json>" line per object, for a cluster whose domain is
CLUSTER_NAME.BASE_DOMAIN. Every field the rename overwrites must already exist, since
recert treats a missing field as a sign it is looking at the wrong object.

JSON-seeded values are not protobuf-decoded, so objects use recert's prost serde field
names where they differ from Kubernetes JSON (OAuthClient `redirectUrIs`,
managedFields `fieldsV1.raw` and Secret data as byte arrays).
"""
import json
import sys


def raw_bytes(obj):
    return list(json.dumps(obj).encode())


def configmap(ns, name, data):
    return ("/kubernetes.io/configmaps/%s/%s" % (ns, name),
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": ns}, "data": data})


def secret(ns, name, data, metadata=None):
    """Secret data values are given as text and stored as byte arrays (prost serde)."""
    data = {k: list(v.encode()) for k, v in data.items()}
    meta = {"name": name, "namespace": ns}
    meta.update(metadata or {})
    return ("/kubernetes.io/secrets/%s/%s" % (ns, name),
            {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": meta, "data": data})


def cluster_scoped(group, plural, kind, name, body):
    obj = {"apiVersion": group + "/v1", "kind": kind, "metadata": {"name": name}}
    obj.update(body)
    return ("/kubernetes.io/%s/%s/%s" % (group, plural, name), obj)


def workload(kind, plural, ns, name, pod_spec):
    return ("/kubernetes.io/%s/%s/%s" % (plural, ns, name), {
        "apiVersion": "apps/v1", "kind": kind, "metadata": {"name": name, "namespace": ns},
        "spec": {"selector": {"matchLabels": {"app": name}},
                 "template": {"metadata": {"labels": {"app": name}}, "spec": pod_spec}},
    })


def container(name, env=None, args=None):
    c = {"name": name, "image": name + ":latest"}
    if env is not None:
        c["env"] = [{"name": k, "value": v} for k, v in env]
    if args is not None:
        c["args"] = args
    return c


def route(ns, name, host):
    return ("/openshift.io/routes/%s/%s" % (ns, name), {
        "apiVersion": "route.openshift.io/v1", "kind": "Route", "metadata": {"name": name, "namespace": ns},
        "spec": {"host": host, "to": {"kind": "Service", "name": name, "weight": 100}, "alternateBackends": []},
        "status": {"ingress": [{"host": host, "routerName": "default", "conditions": []}]},
    })


def oauth_client(name, uri):
    return ("/openshift.io/oauth/clients/%s" % name, {
        "apiVersion": "oauth.openshift.io/v1", "kind": "OAuthClient",
        "metadata": {"name": name, "managedFields": [{
            "manager": "authentication-operator", "operation": "Apply", "apiVersion": "oauth.openshift.io/v1",
            "fieldsType": "FieldsV1",
            "fieldsV1": {"raw": raw_bytes({"f:redirectURIs": {'v:"%s"' % uri: {}}})}}]},
        "redirectUrIs": [uri],
        "additionalSecrets": [],
        "scopeRestrictions": [],
        "grantMethod": "auto",
    })


def fixtures(name, base_domain, infra_id):
    domain = "%s.%s" % (name, base_domain)
    apps = "apps." + domain
    api_url = "https://api.%s:6443" % domain
    api_int_url = "https://api-int.%s:6443" % domain
    oauth = "https://oauth-openshift." + apps
    oauth_metadata = json.dumps({"issuer": oauth, "authorization_endpoint": oauth + "/oauth/authorize",
                                 "token_endpoint": oauth + "/oauth/token"})
    router_certs_managed = {"metadata": {"managedFields": [{
        "manager": "ingress-operator", "operation": "Update", "apiVersion": "v1", "fieldsType": "FieldsV1",
        "fieldsV1": {"raw": raw_bytes({"f:data": {"f:" + apps: {}}})}}]}}
    install_config = "apiVersion: v1\nbaseDomain: %s\nmetadata:\n  name: %s\n" % (base_domain, name)
    cli_config = {"oauthConfig": {"loginURL": api_url, "assetPublicURL": "https://console-openshift-console." + apps,
                                  "masterPublicURL": oauth},
                  "servingInfo": {"namedCertificates": [{"names": ["*." + apps]}]}}

    out = [
        secret("openshift-authentication", "v4-0-config-system-router-certs", {apps: "router-cert-pem"}, router_certs_managed["metadata"]),
        secret("openshift-config-managed", "router-certs", {apps: "router-cert-pem"}, router_certs_managed["metadata"]),
        ("/kubernetes.io/operator.openshift.io/ingresscontrollers/openshift-ingress-operator/default", {
            "apiVersion": "operator.openshift.io/v1", "kind": "IngressController",
            "metadata": {"name": "default", "namespace": "openshift-ingress-operator"},
            "spec": {}, "status": {"domain": apps}}),
        secret("openshift-kube-apiserver", "external-loadbalancer-serving-certkey", {},
               {"annotations": {"auth.openshift.io/certificate-hostnames": "api." + domain}}),
        secret("openshift-kube-apiserver", "internal-loadbalancer-serving-certkey", {},
               {"annotations": {"auth.openshift.io/certificate-hostnames": "api-int." + domain}}),
        configmap("openshift-apiserver", "config", {"config.yaml": json.dumps({"routingConfig": {"subdomain": apps}})}),
        cluster_scoped("operator.openshift.io", "openshiftapiservers", "OpenShiftAPIServer", "cluster", {
            "spec": {"logLevel": "Normal", "observedConfig": {"routingConfig": {"subdomain": apps}}}}),
        cluster_scoped("operator.openshift.io", "kubeapiservers", "KubeAPIServer", "cluster", {
            "spec": {"observedConfig": {"apiServerArguments": {"service-account-jwks-uri": [api_int_url + "/openid/v1/jwks"]}}}}),
        cluster_scoped("operator.openshift.io", "kubecontrollermanagers", "KubeControllerManager", "cluster", {
            "spec": {"observedConfig": {"extendedArguments": {"cluster-name": [infra_id]}}}}),
        cluster_scoped("operator.openshift.io", "authentications", "Authentication", "cluster", {
            "spec": {"logLevel": "Normal", "observedConfig": {
                "oauthAPIServer": {"apiServerArguments": {}},
                "oauthServer": cli_config}}}),
        configmap("openshift-authentication", "v4-0-config-system-cliconfig",
                  {"v4-0-config-system-cliconfig": json.dumps(cli_config)}),
        configmap("openshift-authentication", "v4-0-config-system-metadata", {"oauthMetadata": oauth_metadata}),
        configmap("openshift-config-managed", "oauth-openshift", {"oauthMetadata": oauth_metadata}),
        cluster_scoped("config.openshift.io", "consoles", "Console", "cluster", {
            "spec": {}, "status": {"consoleURL": "https://console-openshift-console." + apps}}),
        cluster_scoped("config.openshift.io", "dnses", "DNS", "cluster", {"spec": {"baseDomain": domain}}),
        cluster_scoped("config.openshift.io", "infrastructures", "Infrastructure", "cluster", {
            "spec": {}, "status": {"apiServerInternalURI": api_int_url, "apiServerURL": api_url,
                                   "infrastructureName": infra_id}}),
        cluster_scoped("config.openshift.io", "ingresses", "Ingress", "cluster", {
            "spec": {"domain": apps},
            "status": {"componentRoutes": [{"name": "oauth-openshift", "namespace": "openshift-authentication",
                                            "defaultHostname": "oauth-openshift." + apps}]}}),
        configmap("openshift-config-managed", "monitoring-shared-config", {
            "alertmanagerTenancyHost": "alertmanager-main-openshift-monitoring." + apps,
            "alertmanagerUserWorkloadHost": "alertmanager-user-workload-openshift-user-workload-monitoring." + apps,
            "prometheusPublicURL": "https://prometheus-k8s-openshift-monitoring." + apps,
            "thanosPublicURL": "https://thanos-querier-openshift-monitoring." + apps}),
        configmap("openshift-ovn-kubernetes", "ovnkube-config", {
            "ovnkube.conf": '[default]\nmtu="1400"\n\n[kubernetes]\napiserver="%s"\n' % api_int_url}),
        configmap("kube-system", "cluster-config-v1", {"install-config": install_config}),
        configmap("openshift-etcd", "cluster-config-v1", {"install-config": install_config}),
        workload("Deployment", "deployments", "openshift-cluster-version", "cluster-version-operator",
                 {"containers": [container("cluster-version-operator", env=[("KUBERNETES_SERVICE_HOST", "api-int." + domain)])]}),
        workload("DaemonSet", "daemonsets", "openshift-multus", "multus",
                 {"containers": [container("kube-multus", env=[("KUBERNETES_SERVICE_HOST", "api-int." + domain)])]}),
        workload("DaemonSet", "daemonsets", "openshift-multus", "multus-additional-cni-plugins",
                 {"initContainers": [container("whereabouts-cni", env=[("KUBERNETES_SERVICE_HOST", "api-int." + domain)])],
                  "containers": [container("kube-multus-additional-cni-plugins")]}),
        workload("Deployment", "deployments", "openshift-ingress", "router-default",
                 {"containers": [container("router", env=[("ROUTER_CANONICAL_HOSTNAME", "router-default." + apps),
                                                          ("ROUTER_DOMAIN", apps)])]}),
        route("openshift-ingress-canary", "canary", "canary-openshift-ingress-canary." + apps),
        route("openshift-monitoring", "prometheus-k8s", "prometheus-k8s-openshift-monitoring." + apps),
        route("openshift-monitoring", "prometheus-k8s-federate", "prometheus-k8s-federate-openshift-monitoring." + apps),
        route("openshift-monitoring", "thanos-querier", "thanos-querier-openshift-monitoring." + apps),
        route("openshift-authentication", "oauth-openshift", "oauth-openshift." + apps),
        ("/kubernetes.io/machineconfiguration.openshift.io/controllerconfigs/machine-config-controller", {
            "apiVersion": "machineconfiguration.openshift.io/v1", "kind": "ControllerConfig",
            "metadata": {"name": "machine-config-controller"},
            "spec": {"dns": {"spec": {"baseDomain": domain}},
                     "infra": {"status": {"apiServerInternalURI": api_int_url, "apiServerURL": api_url,
                                          "infrastructureName": infra_id}}}}),
        oauth_client("openshift-browser-client", oauth + "/oauth/token/display"),
        oauth_client("openshift-challenging-client", oauth + "/oauth/token/implicit"),
        workload("DaemonSet", "daemonsets", "openshift-machine-config-operator", "machine-config-server",
                 {"containers": [container("machine-config-server",
                                           args=["start", "--apiserver-url=" + api_int_url])]}),
    ]
    return out


def main():
    name, base_domain, infra_id = sys.argv[1:4]
    for key, obj in fixtures(name, base_domain, infra_id):
        print("%s\t%s" % (key, json.dumps(obj)))


if __name__ == "__main__":
    main()
