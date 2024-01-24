#!/bin/bash

set -ex

RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
BACKUP_IMAGE=${1:-quay.io/otuchfel/ostbackup:seed}
AUTH_FILE=${AUTH_FILE:-~/omer-ps}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

cd "$SCRIPT_DIR"

if [[ ! -f ouger/go.mod ]] || [[ ! -f etcddump/Cargo.toml ]]; then
	echo "ouger or etcddump not found, please run git submodule update --init"
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

until etcdctl endpoint health; do
	sleep 1
done

sudo unshare --mount -- bash -c "mount --bind /dev/null .cargo/config.toml && sudo -u $USER env PATH=$PATH \
    cargo run --manifest-path etcddump/Cargo.toml --release -- --etcd-endpoint localhost:2379 --output-dir backup/etcd_orig \
"

# Only use config if WITH_CONFIG is set
if [[ -n "$WITH_CONFIG" ]]; then
	echo "Using config"
	RECERT_CONFIG=<(echo "
dry_run: false
etcd_endpoint: localhost:2379
static_dirs:
- backup/etc/kubernetes
- backup/var/lib/kubelet
- backup/etc/machine-config-daemon
static_files:
- backup/etc/mcs-machine-config-content.json
cn_san_replace_rules:
- api-int.seed.redhat.com:api-int.new-name.foo.com
- api.seed.redhat.com:api.new-name.foo.com
- '*.apps.seed.redhat.com:*.apps.new-name.foo.com'
- 192.168.126.10:192.168.127.11
use_cert_rules:
- |
    -----BEGIN CERTIFICATE-----
    MIICyzCCAbMCFAoie5EUqnUAHimqxbJBHV0MGVbwMA0GCSqGSIb3DQEBCwUAMCIx
    IDAeBgNVBAMMF2FkbWluLWt1YmVjb25maWctc2lnbmVyMB4XDTI0MDEwOTEzMTky
    NVoXDTI0MDIwODEzMTkyNVowIjEgMB4GA1UEAwwXYWRtaW4ta3ViZWNvbmZpZy1z
    aWduZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2fz96uc8fDoNV
    RaBB9iQ+i5Y76IZf0XOdGID8WVaqPlqH+NgLUaFa39T+78FhZW3794Lbeyu/PnYT
    ufMyKnJEulVO7W7gPHaqWyuN08/m6SH5ycTEgUAXK1q1yVR/vM6HnV/UPUCfbDaW
    RFOrUgGNwNywhEjqyzyUxJFixxS6Rk7JmouROD2ciNhBn6wNFByVHN9j4nQUOhXC
    A0JjuiPH7ybvcHjmg3mKDJusyVq4pl0faahOxn0doILfXaHHwRxyEnP3V3arpPer
    FvwlHh2Cfat+ijFPSD9pN3KmoeAviOHZVLQ/jKzkQvzlvva3mhEpLE5Zje1lMpvq
    fjDheW9bAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAC7oi/Ht0lidcx6XvOBz6W1m
    LU02e2yHuDzw6E3WuNoqAdPpleFRV4mLDnv8mEavH5sje0L5veHtOq3Ny4pc06B+
    ETB2aCW4GQ4mPvN9Jyi6sxLQQaVLpFrtPPB08NawNbbcYWUrAihO1uIXLhaCYZWw
    H3aWlqRvGECazYZIPcFoV20jygrcwMhixSZjYyHhJN0LYO5sjiKcMnI8EkHuqE17
    7CPogicZte+m49Mo+f7b8asmKBSafdTUSVAt9Q3Fc3PTJSMW5lxfx1vIR/og33WJ
    BgIejfD1dYW2Fp02z5sF6Pw6vhobpfDYgsTAKNonh5P6NxMiD14eQxYrNJ6DAF0=
    -----END CERTIFICATE-----
cluster_rename: new-name:foo.com:some-random-infra-id
summary_file: summary.yaml
summary_file_clean: summary_redacted.yaml
extend_expiration: true
force_expire: false
threads: 1
") cargo run --release
else
	cargo run --release -- \
		--etcd-endpoint localhost:2379 \
		--static-dir backup/etc/kubernetes \
		--static-dir backup/var/lib/kubelet \
		--static-dir backup/etc/machine-config-daemon \
		--static-file backup/etc/mcs-machine-config-content.json \
		--cn-san-replace api-int.seed.redhat.com:api-int.new-name.foo.com \
		--cn-san-replace api.seed.redhat.com:api.new-name.foo.com \
		--cn-san-replace *.apps.seed.redhat.com:*.apps.new-name.foo.com \
		--cn-san-replace 192.168.126.10:192.168.127.11 \
		--cluster-rename new-name:foo.com:some-random-infra-id \
		--summary-file summary.yaml \
		--summary-file-clean summary_redacted.yaml \
		--extend-expiration
	# --regenerate-server-ssh-keys backup/etc/ssh/ \
fi

sudo unshare --mount -- bash -c "mount --bind /dev/null .cargo/config.toml && sudo -u $USER env PATH=$PATH \
    cargo run --manifest-path etcddump/Cargo.toml --release -- --etcd-endpoint localhost:2379 --output-dir backup/etcd \
"

# meld backup/etc_orig backup/etc
# meld backup/var_orig backup/var
# meld backup/etcd_orig backup/etcd
