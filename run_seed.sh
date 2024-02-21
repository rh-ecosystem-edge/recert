#!/bin/bash

set -ex

RELEASE_IMAGE=quay.io/openshift-release-dev/ocp-release:4.13.0-x86_64
BACKUP_IMAGE=${1:-quay.io/otuchfel/ostbackup:seed}
AUTH_FILE=${AUTH_FILE:-~/seed-pull-secret}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

cd "$SCRIPT_DIR"

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
	RECERT_CONFIG=<(echo '
dry_run: false
etcd_endpoint: localhost:2379
crypto_dirs:
- backup/etc/kubernetes
- backup/var/lib/kubelet
- backup/etc/machine-config-daemon
crypto_files:
- backup/etc/mcs-machine-config-content.json
cluster_customization_dirs:
- backup/etc/kubernetes
- backup/var/lib/kubelet
- backup/etc/machine-config-daemon
- backup/etc/pki/ca-trust
cluster_customization_files:
- backup/etc/mcs-machine-config-content.json
cn_san_replace_rules:
- api-int.seed.redhat.com:api-int.new-name.foo.com
- api.seed.redhat.com:api.new-name.foo.com
- "*.apps.seed.redhat.com:*.apps.new-name.foo.com"
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
hostname: test.hostname
ip: 192.168.126.99
kubeadmin_password_hash: "$2a$10$20Q4iRLy7cWZkjn/D07bF.RZQZonKwstyRGH0qiYbYRkx5Pe4Ztyi"
additional_trust_bundle: |
    # Foo
    -----BEGIN CERTIFICATE-----
    MIIDZTCCAk2gAwIBAgIUP+AxIkXJXTEhNGLH2qjmE6Gp0fowDQYJKoZIhvcNAQEL
    BQAwQjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE
    CgwTRGVmYXVsdCBDb21wYW55IEx0ZDAeFw0yNDAzMDExMDIyNTlaFw0yNTAzMDEx
    MDIyNTlaMEIxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAa
    BgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IB
    DwAwggEKAoIBAQC0wzg+7X2Amb5g60g0TstLgC0XnJRZq/YZUUsJMmm3qMb/+GYJ
    AJzHxiycUfbRJtYvjx0SBmAX/kDRVCEQKcN5d/y3zeq709YO40kvouScfstsxM8l
    PFLOmM8/Dqey1WblSJERBLbLherDnMwR7EMXkyZ/AfHUXmhVoIZE9ywsZpNcVW6Z
    7x/+Izbj1s305vrxEkZDw6b3oMG5uooQgP5NZFXSamzJgviP0L/usvbRMtAWphoj
    WhMeNuOdymLwRzm2l+2Qp/JDWktgHccmrbbi1c6pwhsIJBj4KOyb9zROTnYXyS/j
    0b7GzVcffveV6E58rGa2ILyIsCv6gt8LgFnxAgMBAAGjUzBRMB0GA1UdDgQWBBQ5
    nh0SeZxZ969ps+9ywPEoOVasxTAfBgNVHSMEGDAWgBQ5nh0SeZxZ969ps+9ywPEo
    OVasxTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAWxsqfdm8h
    AeNY8vPcRdtB9KYU5sZLs4NtlBFSdn+pHmeXZwwkjQDNhVcEMKdpZI4BpS11Ggwh
    1d3BCCC/5M6yVqm+EMKJvA9VCeM8d1WJ1yVyXcgGuegf8kr3v+lr7Ll59qZGP5Ir
    WwE8WRns7uFOCqYJCxo1VFXitZZuIugr3NUSimBPoJf1hDYdye3K3Q+grF2GyNII
    5Yo+/VSR4ejIvJYAFp91Ycep7S0/+qhFpsjEG0Qw3Ly6WqQoCqdmIsyqFgWHsIlY
    oJxV5wTX/c9DDZLR0VUD19aDV3B9kb7Cf+h7S4RsORWCyi7+58FKkkD6Ryc0I1K6
    xw3RWhfd9o1d
    -----END CERTIFICATE-----



    # All
    # the Bars
    -----BEGIN CERTIFICATE-----
    MIIDZTCCAk2gAwIBAgIULnisjJLte3Vvt4o1f+5vSQg542cwDQYJKoZIhvcNAQEL
    BQAwQjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE
    CgwTRGVmYXVsdCBDb21wYW55IEx0ZDAeFw0yNDAzMDExMDI1MDFaFw0yNTAzMDEx
    MDI1MDFaMEIxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAa
    BgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IB
    DwAwggEKAoIBAQC2dhK7xTnoTB3wN1l3NsLTp5YR0KFfBTjMcDgSzUy/GN79c2cF
    JzSuiYUi7SCmFjn3soNqpXHFzCox6KIs9R6PL4epaQM76EVG/Xy6mdDvFnZvqypi
    wmK6J0AGajOxItYUGb2a3Zmt/2nliW6t8sW/vhovHRu7YROo4uJygIp2UUFct2Lk
    8C7XkJX5RXW+sKTiNddIjhmDFD0vHfvNvQ6AIayJTmXy272+aqYNJWB2wS/2uD3Z
    +WOpiINetCtkASoiE7nzBQw+WsTfeFJH2TnI5pnSaHdLRUQtzoLO0/FgQ5WBfJg5
    aH03DLfQ9GEdzlsOkPOEgHXqDFMjTQCwcue3AgMBAAGjUzBRMB0GA1UdDgQWBBRd
    0Zs+cm0gPHGKoQrerC18Pa3B3zAfBgNVHSMEGDAWgBRd0Zs+cm0gPHGKoQrerC18
    Pa3B3zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAepPrWqB9h
    JkqtgJrP8SkQVulTVKYj66J5JxM5vZR96Z4UnbA3WNxezev0jMCYuV0twHPN8avs
    Jern+/n7vgQ3ziiLVdtrN8PqK1X1apSurVmaiIw4tRcv5TVL5OD95sTyJh5bUBpM
    DGtCTraPZxLIDKm9byunobXtJVcutw4oHKtFy/LlFWePCnvFzvx6ZFswLAXgxhf9
    EtjDf3v0cjDn9yRzjYFrwHiQ53A75YTwFyk21q7Gh1G0yspfBeq7cej2wK1PnfiC
    42TI0UzcqRV4CWDoARMSV8yMLajZ0g1eEreUprwmFcOy17V7KCeV6E8lKb21OU8M
    Ad9q3H0iXjct
    -----END CERTIFICATE-----
summary_file: summary.yaml
summary_file_clean: summary_redacted.yaml
extend_expiration: true
force_expire: false
pull_secret: "{\"auths\":{\"empty_registry\":{\"username\":\"empty\",\"password\":\"empty\",\"auth\":\"ZW1wdHk6ZW1wdHk=\",\"email\":\"\"}}}"
threads: 1
') cargo run --release
else
	# shellcheck disable=2016
	cargo run -- \
		--etcd-endpoint localhost:2379 \
        \
		--crypto-dir backup/etc/kubernetes \
		--crypto-dir backup/var/lib/kubelet \
		--crypto-dir backup/etc/machine-config-daemon \
		--crypto-file backup/etc/mcs-machine-config-content.json \
        \
		--cluster-customization-dir backup/etc/kubernetes \
		--cluster-customization-dir backup/var/lib/kubelet \
		--cluster-customization-dir backup/etc/machine-config-daemon \
		--cluster-customization-dir backup/etc/pki/ca-trust \
		--cluster-customization-file backup/etc/mcs-machine-config-content.json \
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
		--kubeadmin-password-hash '$2a$10$20Q4iRLy7cWZkjn/D07bF.RZQZonKwstyRGH0qiYbYRkx5Pe4Ztyi' \
		--additional-trust-bundle ./hack/dummy_trust_bundle.pem \
		--pull-secret '{"auths":{"empty_registry":{"username":"empty","password":"empty","auth":"ZW1wdHk6ZW1wdHk=","email":""}}}' \
        \
		--summary-file summary.yaml \
		--summary-file-clean summary_redacted.yaml \
        \
		--extend-expiration
	# --regenerate-server-ssh-keys backup/etc/ssh/ \
fi

sudo unshare --mount -- bash -c "mount --bind /dev/null .cargo/config.toml && sudo -u $USER env PATH=$PATH \
    cargo run --manifest-path etcddump/Cargo.toml --release -- --etcd-endpoint localhost:2379 --output-dir backup/etcd \
"

# meld backup/etc_orig backup/etc
# meld backup/var_orig backup/var
# meld backup/etcd_orig backup/etcd
