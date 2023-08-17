# Recert

A tool to regenerate all certificates in a cluster (both in the etcd database
and filesystem files) before it starts. Works by scanning the existing
certificates/keys/jwts, understanding how they relate, and replacing them in an
identical structure, but with newly randomly generated keys and optional
modifications.

# Why

The motivation for creating this tool was the effort to allow users to install
a SNO cluster once in a lab, then copy its disk image for immediate deployment
in many different sites. By running the tool during the first boot of the host,
the new cluster will thus have its own independent secret keys that are
separate from other clusters deployed in the same manner.

# TODO

<details>
  <summary>TODO List</summary>

## Critical
- [ ] Figure out ACM integration - how do we ensure certs relating to the spoke-hub relationship also get regenerated
- [ ] Create new serial numbers for regenerated certs
- [ ] Make sure cert fingerprint matches after key regeneration (also must match signer)
- [ ] Use the same RSA bit size as the original key
- [ ] Don't use RSA everywhere - EC certs/keys should still be EC
    - [ ] Remove the code to adjust the signature algorithm identifer once we've done that as it's no longer needed
- [ ] Leave traces everywhere - PEM comments, resource annotations, etc to indicate that the resource has been modified
- [ ] Create a very informative summary that can be used to debug the cert regen in prod
- [ ] Give users an option to regenerate pointer ignitions
- [ ] Regenerate filesystem standalone token file (localhost-recovery-client-token/token)


## Performance 

- [ ] Consider recalculating machine-config hashes hack to make machine-config start faster
    - [ ] Or just delete `/etc/machine-config-daemon` and hope MCO starts fast enough
- [ ] Delete leases to make operators start faster

## Nice to have
- [ ] Somehow have built-in ouger functionality instead of shelling out to ouger
- [ ] Remove OLM package server hack
- [ ] Somehow reduce binary size
- [ ] Get rid of unnecessary dependencies. Right now we have more than 300
- [ ] Convert from resource YAML to etcd key-value key more gracefuly
- [ ] Find proof that root-ca private key is actually missing
- [ ] Get rid of the external certs list
- [ ] Move to a crypto lib that actually supports hybrid certs (EC signing RSA or vice versa) instead of shelling out to openssl for it
- [ ] When shelling out to openssl to check if cert A signed cert B, construct the command in such a way that if A == B, then it will not give a green result when said cert is not self signed
- [ ] Add warnings when the certs already expired. Plugin idea: extend expiration
- [ ] Fix all code TODO comments

</details>

## Usage examples

### Local Development

#### Requirements

* qemu-nbd
* podman
* [ouger](https://github.com/omertuc/ouger)
* a qcow2 image of a fully installed SNO cluster

#### Config

```bash
# !! Don't forget to change these !!
REPO_DIR=/home/$USER/repos/recert
QCOW2_DIR=/home/$USER/Documents/model6
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
#####################################

CLUSTER_DIR="$REPO_DIR"/cluster-files
BACKUP_CLUSTER_DIR="$REPO_DIR"/cluster-files-backup
ETCD_RESOURCES="machineconfiguration.openshift.io/machineconfigs secrets configmaps validatingwebhookconfigurations apiregistration.k8s.io/apiservices"
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
sudo podman run --network=host -it --authfile ~/repos/bootstrap-in-place-poc/registry-config.json --entrypoint etcd -v $CLUSTER_DIR/etcd:/store ${ETCD_IMAGE} --name editor --data-dir /store
```

#### Run recert

See `./run.sh` example

### Run on SNO POC cluster

#### Requirements

* [ouger](https://github.com/omertuc/ouger)
* [bootstrap-in-place-poc](https://github.com/eranco74/bootstrap-in-place-poc)

#### Config

```bash
# !! Don't forget to change these !!
REPO_DIR=/home/$USER/repos/recert
POC_DIR=/home/$USER/repos/bootstrap-in-place-poc
RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
#####################################

SSH_FLAGS="-o IdentityFile=./ssh-key/key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no core@192.168.126.10"
SSH_HOST="core@192.168.126.10"
ETCD_IMAGE="$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"
```

#### Compile for platform
```bash
RUSTFLAGS='-C target-feature=+crt-static' cargo --manifest-path "$REPO_DIR"/Cargo.toml build --release --target x86_64-unknown-linux-gnu
```

#### Disable control plane & reboot

```bash
ssh $SSH_FLAGS "$SSH_HOST" sudo systemctl disable kubelet
ssh $SSH_FLAGS "$SSH_HOST" sudo systemctl disable crio
ssh $SSH_FLAGS "$SSH_HOST" sudo reboot 
sleep 60
```

#### Run etcd

```bash
ssh $SSH_FLAGS "$SSH_HOST" sudo podman run --network=host --privileged --entrypoint etcd -v /var/lib/etcd:/store ${ETCD_IMAGE} --name editor --data-dir /store
```

#### Copy things

```bash
ssh $SSH_FLAGS "$SSH_HOST" sudo mkdir -p /root/.local/bin
scp $SSH_FLAGS $RECERT/target/x86_64-unknown-linux-gnu/release/recert "$SSH_HOST":recert
scp $SSH_FLAGS $(which ouger) "$SSH_HOST":
scp $SSH_FLAGS "$POC_DIR"/sno-workdir/auth/kubeconfig "$SSH_HOST":

ssh $SSH_FLAGS "$SSH_HOST" sudo cp /home/core/ouger /root/.local/bin/
ssh $SSH_FLAGS "$SSH_HOST" sudo cp /home/core/recert /root/.local/bin/
```

#### Run utility

```bash
ssh $SSH_FLAGS "$SSH_HOST" sudo ulimit -n 999999
ssh $SSH_FLAGS "$SSH_HOST" sudo bash -ic "'recert --etcd-endpoint localhost:2379 --static-dir /etc/kubernetes --static-dir /var/lib/kubelet --static-dir /etc/machine-config-daemon --kubeconfig /home/core/kubeconfig'"
```

#### Copy regenerated kubeconfig back to your machine
```bash
scp $SSH_FLAGS "$SSH_HOST":kubeconfig "$POC_DIR"/sno-workdir/auth/kubeconfig2
```

#### Reboot
```bash
ssh $SSH_FLAGS "$SSH_HOST" sudo systemctl enable kubelet
ssh $SSH_FLAGS "$SSH_HOST" sudo systemctl enable crio
ssh $SSH_FLAGS "$SSH_HOST" sudo reboot 
```

# Image build

export DOCKER_BUILDKIT=1
docker build . -t quay.io/otuchfel/recert:latest
docker push quay.io/otuchfel/recert:latest
