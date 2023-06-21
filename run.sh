#!/bin/bash

set -uo pipefail

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

REPO_DIR=/home/$USER/repos/recert
QCOW2_DIR=/home/$USER/Documents/model6
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
#####################################

CLUSTER_DIR="$REPO_DIR"/cluster-files
BACKUP_CLUSTER_DIR="$REPO_DIR"/cluster-files-backup
ETCD_RESOURCES="secrets configmaps validatingwebhookconfigurations apiregistration.k8s.io/apiservices"
ETCD_CRDS="machineconfiguration.openshift.io/machineconfigs"

# First dump original etcd
dumpdir="$BACKUP_CLUSTER_DIR"/etcd_dump
mkdir -p $dumpdir
rm -rf $dumpdir
endpoints="--endpoints=127.0.0.1:2379"
for key in $(etcdctl $endpoints get /--prefix --keys-only); do
    mkdir -p $(dirname "$dumpdir"/$key)
    (etcdctl $endpoints get --print-value-only $key | head -c -1 | ouger decode >"$dumpdir"/$key.yaml) &
done

for kind in $(echo $ETCD_CRDS); do
	for key in $(etcdctl $endpoints get /kubernetes.io/"$kind"/ --prefix --keys-only); do
		mkdir -p $(dirname $dumpdir/$key)
		(etcdctl $endpoints get --print-value-only $key | head -c -1 | toyaml >"$dumpdir"/$key.yaml) &
	done
done

wait

# Run utility
ulimit -n 999999
cargo run --manifest-path "$REPO_DIR"/Cargo.toml --release -- \
	--etcd-endpoint localhost:2379 \
	--static-dir "$CLUSTER_DIR"/kubernetes \
	--static-dir "$CLUSTER_DIR"/kubelet \
	--static-dir "$CLUSTER_DIR"/machine-config-daemon \
	--cn-san-replace "api-int.test-cluster.redhat.com api-int.new-name.foo.com" \
	--cn-san-replace "api.test-cluster.redhat.com api.new-name.foo.com" \
	--cn-san-replace "*.apps.test-cluster.redhat.com *.apps.new-name.foo.com" \
	--cluster-rename new-name,foo.com

# Dump etcd after changes
dumpdir="$CLUSTER_DIR"/etcd_dump
mkdir -p "$dumpdir"
rm -rf "$dumpdir"
endpoints="--endpoints=127.0.0.1:2379"
for kind in $(echo $ETCD_RESOURCES); do
	for key in $(etcdctl $endpoints get /kubernetes.io/"$kind"/ --prefix --keys-only); do
		mkdir -p $(dirname "$dumpdir"/$key)
		(etcdctl $endpoints get --print-value-only $key | head -c -1 | ouger decode >"$dumpdir"/$key.yaml) &
	done
done
for kind in $(echo $ETCD_CRDS); do
	for key in $(etcdctl $endpoints get /kubernetes.io/"$kind"/ --prefix --keys-only); do
		mkdir -p $(dirname $dumpdir/$key)
		(etcdctl $endpoints get --print-value-only $key | head -c -1 | toyaml >"$dumpdir"/$key.yaml) &
	done
done

meld "$BACKUP_CLUSTER_DIR" "$CLUSTER_DIR"
