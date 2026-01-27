#!/bin/bash

set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

cd "$SCRIPT_DIR"

RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.22.0-ec.0-x86_64
BACKUP_IMAGE=${1:-quay.io/otuchfel/ostbackup:seed}
AUTH_FILE=${AUTH_FILE:-~/seed-pull-secret}

if [[ ! -f ouger/go.mod ]] || [[ ! -f etcddump/Cargo.toml ]]; then
	echo "ouger or etcddump not found, please run git submodule update --init"
	exit 1
fi

if [ ! -s "${AUTH_FILE}" ]; then
	echo "auth file ${AUTH_FILE} is empty"
	exit 1
fi

if [[ ! -d backup ]]; then
	podman pull "$BACKUP_IMAGE"
	podman save --format=oci-dir "$BACKUP_IMAGE" -o backup
	# shellcheck disable=2002
	cat backup/blobs/sha256/"$(cat backup/blobs/sha256/"$(cat backup/index.json | jq '.manifests[0].digest' -r | cut -d ':' -f2)" | jq '.layers[0].digest' -r | cut -d ':' -f2)" | tar -xz -C backup
fi

rm -rf backup/etc backup/var backup/etc_orig backup/var_orig backup/etcd_orig backup/etcd

tar -C backup -xzf backup/etc.tgz
tar -C backup -xzf backup/var.tgz

mkdir -p backup/etc_orig backup/var_orig backup/etcd_orig backup/etcd

tar -C backup/etc_orig -xzf backup/etc.tgz etc --strip-components=1
tar -C backup/var_orig -xzf backup/var.tgz var --strip-components=1

podman kill editor >/dev/null || true
podman rm editor >/dev/null || true

PATH=$PATH:$(go env GOPATH)/bin

pushd ouger && go install cmd/server/ouger_server.go && popd
pushd ouger && go install cmd/ouger/ouger.go && popd

ETCD_IMAGE=${ETCD_IMAGE:-"$(oc adm release extract --from="$RELEASE_IMAGE" --file=image-references | jq '.spec.tags[] | select(.name == "etcd").from.name' -r)"}

mkdir -p "$PWD"/backup/var/lib/etcd
podman run --network=host --name editor \
	--detach \
	--authfile "${AUTH_FILE}" \
	--entrypoint etcd \
	-v "$PWD/backup/var/lib/etcd:/store:rw,Z" \
	"${ETCD_IMAGE}" --name editor --data-dir /store

until curl -s localhost:2379/health | jq -e '.health == "true"' >/dev/null; do
	sleep 1
done

sudo unshare --mount -- bash -c "mount --bind /dev/null .cargo/config.toml && sudo -u $USER env PATH=$PATH \
    cargo run --manifest-path etcddump/Cargo.toml --release -- --etcd-endpoint localhost:2379 --output-dir backup/etcd_orig \
"

# Only use config if WITH_CONFIG is set
if [[ -n "$WITH_CONFIG" ]]; then
	echo "Using config"
	# shellcheck disable=2016
	RECERT_CONFIG="$SCRIPT_DIR/hack/dummy_config.yaml" cargo run --release
else
	# shellcheck disable=2016
	cargo run -- \
		--etcd-endpoint localhost:2379 \
        \
		--crypto-dir backup/etc/kubernetes \
		--crypto-dir backup/var/lib/kubelet \
		--crypto-dir backup/etc/machine-config-daemon \
		--crypto-file backup/etc/mcs-machine-config-content.json \
		--cluster-customization-file backup/etc/chrony.conf \
        \
		--cluster-customization-dir backup/etc/kubernetes \
		--cluster-customization-dir backup/var/lib/kubelet \
		--cluster-customization-dir backup/etc/machine-config-daemon \
		--cluster-customization-dir backup/etc/pki/ \
		--cluster-customization-file backup/etc/mcs-machine-config-content.json \
        --cluster-customization-file backup/etc/mco/proxy.env \
        \
		--cn-san-replace api-int.seed.redhat.com:api-int.new-name.foo.com \
		--cn-san-replace api.seed.redhat.com:api.new-name.foo.com \
		--cn-san-replace *.apps.seed.redhat.com:*.apps.new-name.foo.com \
		--cn-san-replace 192.168.126.10:192.168.127.11 \
		--use-cert ./hack/dummy_use_cert.crt \
        \
		--cluster-rename new-name:foo.com:some-random-infra-id \
		--hostname test.hostname \
		--ip 192.168.126.99 \
		--install-config 'additionalTrustBundlePolicy: Proxyonly
apiVersion: v1
baseDomain: ibo0.redhat.com
bootstrapInPlace:
  installationDisk: /dev/disk/by-path/pci-0000:04:00.0
compute:
- architecture: amd64
  hyperthreading: Enabled
  name: worker
  platform: {}
  replicas: 0
controlPlane:
  architecture: amd64
  hyperthreading: Enabled
  name: master
  platform: {}
  replicas: 1
metadata:
  creationTimestamp: null
  name: seed
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  machineNetwork:
  - cidr: 192.168.126.0/24
  networkType: OVNKubernetes
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
publish: External
pullSecret: ""
sshKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDThIOETj6iTvbCaNv15tZg121nWLcwtJuZofc1QS5iAdw8C8fN2R39cSW/ambikl2Fr6YNBBVR3znbtmattOyWyxAOFUfdY0aw0MqZb4LWLf04q6X0KsWIYWaV3ol0KxTzgvX38i/IU42XQfJwMYFE8dQ15TZ7l+FTKKi3SUPXLuy/9CXRfaCDZ2dKMcCkelkTr0KR1HdjiKQ86rMfk9JUbAf7D29aAQq4h1WNnHMM9vnbqN7MW9L8ebn/lCTJjGQ56r0UmurgyIEMt0P+CGp1e4AUNKYsPoYFB0GNwUkr/rB8LeuCOaZcoWdYXlUJaN45GjtCDon56+AoMA9V8tYkV6HqyFwGQjoGKI1cRCHXDJnGyAbMd9OK94TWJmNvtdHkbSURHyw2G7otZpAkRuEvMP0C7R+3JmuxrDA8yaUgWvgccqGcmFl1krClksW6KrAXNlwhZ4QOAMhDrXwwPfOOQoG82zPpg+g9gZQIhkro1Cje4bmWz5z5fiuDloTq1vc=
  root@edge-01.edge.lab.eng.rdu2.redhat.com' \
		--machine-network-cidr '192.168.127.0/24' \
		--kubeadmin-password-hash '$2a$10$20Q4iRLy7cWZkjn/D07bF.RZQZonKwstyRGH0qiYbYRkx5Pe4Ztyi' \
		--pull-secret '{"auths":{"empty_registry":{"username":"empty","password":"empty","auth":"ZW1wdHk6ZW1wdHk=","email":""}}}' \
		--chrony-config 'pool 0.rhel.pool.ntp.org iburst
driftfile /var/lib/chrony/drift
server test iburst
' \
        \
		--summary-file summary.yaml \
		--summary-file-clean summary_redacted.yaml \
        \
		--extend-expiration
    # --proxy 'http://registry.kni-qe-0.lab.eng.rdu2.redhat.com:3128|http://registry.kni-qe-0.lab.eng.rdu2.redhat.com:3130|.cluster.local,.kni-qe-2.lab.eng.rdu2.redhat.com,.svc,127.0.0.1,2620:52:0:11c::/64,2620:52:0:11c::1,2620:52:0:11c::10,2620:52:0:11c::11,2620:52:0:199::/64,api-int.kni-qe-2.lab.eng.rdu2.redhat.com,fd01::/48,fd02::/112,localhost|http://registry.kni-qe-0.lab.eng.rdu2.redhat.com:3128|http://registry.kni-qe-0.lab.eng.rdu2.redhat.com:3130|.cluster.local,.kni-qe-2.lab.eng.rdu2.redhat.com,.svc,127.0.0.1,2620:52:0:11c::/64,2620:52:0:11c::1,2620:52:0:11c::10,2620:52:0:11c::11,2620:52:0:199::/64,api-int.kni-qe-2.lab.eng.rdu2.redhat.com,fd01::/48,fd02::/112,localhost,moreproxy' \
    # --user-ca-bundle ./hack/dummy_trust_bundle.pem \
    # --proxy-trusted-ca-bundle user-ca-bundle: \
	# --regenerate-server-ssh-keys backup/etc/ssh/ \
fi

sudo unshare --mount -- bash -c "mount --bind /dev/null .cargo/config.toml && sudo -u $USER env PATH=$PATH \
    cargo run --manifest-path etcddump/Cargo.toml --release -- --etcd-endpoint localhost:2379 --output-dir backup/etcd \
"

# meld backup/etc_orig backup/etc
# meld backup/var_orig backup/var
# meld backup/etcd_orig backup/etcd
