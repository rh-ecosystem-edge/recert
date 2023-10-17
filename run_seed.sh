#!/bin/bash

set -e

RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64

BACKUP_IMAGE=${1:-quay.io/otuchfel/ostbackup:backup}

if [[ ! -d backup ]]; then
    podman pull $BACKUP_IMAGE
    podman save --format=oci-dir $BACKUP_IMAGE  -o backup
    cat backup/blobs/sha256/$(cat backup/blobs/sha256/$(cat backup/index.json | jq '.manifests[0].digest' -r | cut -d ':' -f2) | jq '.layers[0].digest' -r | cut -d ':' -f2) | tar -xz -C backup
fi

rm -rf backup/etc backup/var backup/etc_orig backup/var_orig backup/etcd_orig backup/etcd

tar -C backup -xzf backup/etc.tgz
tar -C backup -xzf backup/var.tgz

mkdir -p backup/etc_orig backup/var_orig backup/etcd_orig backup/etcd

tar -C backup/etc_orig -xzf backup/etc.tgz etc --strip-components=1
tar -C backup/var_orig -xzf backup/var.tgz var --strip-components=1

podman kill editor >/dev/null || true
podman rm editor >/dev/null || true

pushd ouger && go install cmd/server/ouger_server.go && popd

ETCD_IMAGE=${ETCD_IMAGE:-"$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"}
podman run --network=host --name editor \
    --detach \
    --authfile ~/repos/bootstrap-in-place-poc/registry-config.json \
    --entrypoint etcd \
    -v $PWD/backup/var/lib/etcd:/store \
    ${ETCD_IMAGE} --name editor --data-dir /store

until etcdctl endpoint health; do
    sleep 1
done

cargo run --manifest-path etcddump/Cargo.toml --release -- --etcd-endpoint localhost:2379 --output-dir backup/etcd_orig

cargo run --release -- \
    --etcd-endpoint localhost:2379 \
    --static-dir backup/etc/kubernetes \
    --static-dir backup/var/lib/kubelet \
    --static-dir backup/etc/machine-config-daemon \
    --static-file backup/etc/mcs-machine-config-content.json  \
    --cn-san-replace api-int.test-cluster.redhat.com:api-int.new-name.foo.com \
    --cn-san-replace api.test-cluster.redhat.com:api.new-name.foo.com \
    --cn-san-replace *.apps.test-cluster.redhat.com:*.apps.new-name.foo.com \
    --cn-san-replace 192.168.127.10:192.168.127.11 \
    --summary-file summary.yaml \
    --extend-expiration
    # --regenerate-server-ssh-keys backup/etc/ssh/ \

cargo run --manifest-path etcddump/Cargo.toml --release -- --etcd-endpoint localhost:2379 --output-dir backup/etcd

# meld backup/etc_orig backup/etc
# meld backup/var_orig backup/var
# meld backup/etcd_orig backup/etcd
