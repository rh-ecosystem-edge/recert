# Recert

A tool to regenerate all cryptographic objects in a cluster (both in the etcd
database and filesystem files) before it starts. Works by scanning the existing
certificates/keys/jwts, understanding how they relate, and replacing them in an
identical structure, but with new randomly generated keys and optional
customizations.

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

You need protoc, podman, openssl, etcdctl, meld, and an IBU seed image. Then
run `./run_seed.sh <seed pullspec>`

On Fedora a lot of these can be installed using: `sudo dnf install protobuf-compiler podman openssl etcd meld`

### Run on a cluster

See [sno-relocation-poc](https://github.com/eranco74/sno-relocation-poc)

# Image build

```bash
export DOCKER_BUILDKIT=1
docker build . -t recert
```

# TODO

<details>
  <summary>TODO List</summary>

- [ ] Remove OLM package server hack
- [ ] Convert from resource YAML to etcd key-value key more gracefully
- [ ] Find proof that root-ca private key is actually missing
- [ ] When shelling out to openssl to check if cert A signed cert B, construct the command in such a way that if A == B, then it will not give a green result when said cert is not self signed
- [ ] Fix all code TODO comments

</details>

