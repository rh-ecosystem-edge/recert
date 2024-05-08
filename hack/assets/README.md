# Synchronizing OpenShift JSON assets

This Go tool downloads specific YAML OpenShift manifests for the specified OCP release, encodes them in JSON and stores them under `src/bindata` to be included in the recert binary. Recert can then compute the spec-hash annotations of those components without worrying about potential JSON encoding differences between Go and Rust. 

## TL;DR

The supported manifests are:

- OpenShift apiserver deployment, managed by the cluster-openshift-apiserver-operator
- OpenShift oauth-apiserver deployment, managed by the cluster-authentication-operator

Syncing the assets:

```shell
# first make sure you have installed a Go version > 1.22, then
go run ./sync.go
```

## Elaborating on JSON encoding differences

The following [Go JSON encoding](https://pkg.go.dev/encoding/json#Marshal) rules are not implemented in Rust's [serde_json](https://docs.rs/serde_json/latest/serde_json/):

- Go map keys are lexicographically sorted
- JSON strings are coerced to valid UTF-8, so that they will be safe to embed inside HTML <script> tags

## Simulating the respective OpenShift cluster operators

After downloading the specified YAML manifests, we add and/or edit various fields of the latter, in order to end up with the same JSON manifests on which the respective cluster operators use to compute the spec-hash annotations. 

The steps we try to simulate can be found here:

- [OpenShift APIServer sync](https://github.com/openshift/cluster-openshift-apiserver-operator/blob/release-4.16/pkg/operator/workload/workload_openshiftapiserver_v311_00_sync.go#L350)
- [OpenShift OAuth APIServer sync](https://github.com/openshift/cluster-authentication-operator/blob/release-4.16/pkg/operator/workload/sync_openshift_oauth_apiserver.go#L131)

## Templating the required annotations

Part of the JSON manifest we need to compute the spec-hash on are annotations that need to be re-computed. For that reason, we add template variables to be replaced in recert, in the following format `${<variable name>}`.
