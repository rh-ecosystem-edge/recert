# See README.Konflux.md before editing this Dockerfile

# build stage
FROM registry.redhat.io/rhel9-4-els/rhel:9.4@sha256:0151b61e6e4c43a41929c7822697ce1c2b5b08cee0f887ab775152fabbb665c0 AS build-image

WORKDIR /app

COPY . .

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all

RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4@sha256:f4c5d46c3f582ecf9eab1f5625bb5200d9ab1cee6ae96160d4877c3d2488a49a AS runtime-image

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all

WORKDIR /app

COPY --from=build-image /app/target/release/recert /usr/local/bin

ENTRYPOINT ["/usr/local/bin/recert"]
