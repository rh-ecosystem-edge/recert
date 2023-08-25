#!/bin/bash

set -uo pipefail

REPO_DIR=/home/$USER/repos/recert
CLUSTER_DIR="$REPO_DIR"/cluster-files
BACKUP_CLUSTER_DIR="$REPO_DIR"/cluster-files-backup

function dump {
	dumpdir="$1"
    echo "Dumping etcd to $dumpdir"
	mkdir -p "$dumpdir"
	rm -rf "$dumpdir"
	endpoints="--endpoints=127.0.0.1:2379"
	for key in $(etcdctl $endpoints get --prefix / --keys-only); do
		mkdir -p $(dirname "$dumpdir/$key")
		(etcdctl $endpoints get --print-value-only "$key" | head -c -1 | ouger decode >"$dumpdir/$key.yaml") &
	done
}

# First dump original etcd
dump "$BACKUP_CLUSTER_DIR/etcd_dump"

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
	--cluster-rename new-name,foo.com \
	--use-cert example.crt

# Dump etcd after changes
dump "$CLUSTER_DIR/etcd_dump"

meld "$BACKUP_CLUSTER_DIR" "$CLUSTER_DIR"

