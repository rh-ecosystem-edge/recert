# Recert

A tool to regenerate all cryptographic objects in a cluster (both in the etcd
database and filesystem files) before it starts. Works by scanning the existing
certificates/keys/jwts, understanding how they relate, and replacing them in an
identical structure, but with newly randomly generated keys and optional
modifications.

# Why

The motivation for creating this tool was the effort to allow users to install
a SNO cluster once in a lab, then copy its disk image for immediate deployment
in many different sites. By running the tool during the first boot of a host
from said image, the new cluster will then have its own independent secret keys
that are separate from other clusters deployed in the same manner.

# Documentation

For more information see the [design doc](docs/design.md)

## Usage examples

### Local Development

<details>
  <summary>Click here for more information</summary>

#### Requirements

* qemu-nbd
* podman
* [ouger](https://github.com/omertuc/ouger)
* a qcow2 image of a fully installed SNO cluster
* meld

#### Config

```bash
# !! Don't forget to change these !!
REPO_DIR=/home/$USER/repos/recert
QCOW2_DIR=/home/$USER/Documents/model6
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
#####################################

CLUSTER_DIR="$REPO_DIR"/cluster-files
BACKUP_CLUSTER_DIR="$REPO_DIR"/cluster-files-backup
```

#### Create a local copy of cluster files

```bash
# Mount disk
cd "$QCOW2_DIR"
sudo modprobe nbd
sudo qemu-nbd --connect=/dev/nbd0 model.qcow2
mkdir -p sno_disk
sudo mount /dev/nbd0p4 sno_disk

# Delete previous copies of the important directories
sudo rm -rf "$BACKUP_CLUSTER_DIR"/
sudo mkdir -p "$BACKUP_CLUSTER_DIR"/
sudo cp -r "$QCOW2_DIR"/sno_disk/ostree/deploy/rhcos/var/lib/etcd "$BACKUP_CLUSTER_DIR"/etcd
sudo cp -r "$QCOW2_DIR"/sno_disk/ostree/deploy/rhcos/deploy/*/etc/kubernetes "$BACKUP_CLUSTER_DIR"/kubernetes
sudo cp -r "$QCOW2_DIR"/sno_disk/ostree/deploy/rhcos/deploy/*/etc/machine-config-daemon "$BACKUP_CLUSTER_DIR"/machine-config-daemon
sudo cp -r "$QCOW2_DIR"/sno_disk/ostree/deploy/rhcos/var/lib/kubelet "$BACKUP_CLUSTER_DIR"/kubelet

sudo chown -R $USER:$USER "$BACKUP_CLUSTER_DIR"/
```

#### Run etcd

```bash
rm -rf "$CLUSTER_DIR/" 
cp -r "$BACKUP_CLUSTER_DIR/" "$CLUSTER_DIR/" 
ETCD_IMAGE="$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"
sudo podman run --network=host -it --authfile ~/repos/bootstrap-in-place-poc/registry-config.json --entrypoint etcd -v $CLUSTER_DIR/etcd:/store:Z ${ETCD_IMAGE} --name editor --data-dir /store
```

#### Run recert

See `./run.sh` example

</details>

### Run on SNO POC cluster

See [sno-relocation-poc](https://github.com/eranco74/sno-relocation-poc)


# Image build

```bash
export DOCKER_BUILDKIT=1
docker build . -t quay.io/recert/recert:latest
docker push quay.io/recert/recert:latest
```

# TODO

<details>
  <summary>TODO List</summary>

- [ ] Remove OLM package server hack
- [ ] Convert from resource YAML to etcd key-value key more gracefuly
- [ ] Find proof that root-ca private key is actually missing
- [ ] When shelling out to openssl to check if cert A signed cert B, construct the command in such a way that if A == B, then it will not give a green result when said cert is not self signed
- [ ] Fix all code TODO comments

</details>

