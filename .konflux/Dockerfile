# See README.Konflux.md before editing this Dockerfile

# build stage
FROM registry.redhat.io/rhel9-4-els/rhel:9.4@sha256:f4cc9022a5925c48bb6e89c26a8b82de66873c8211ec5be9a64c8e5847a6dc73 AS build-image

WORKDIR /app

COPY . .

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all

RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4@sha256:65e57c845402711c5515af0989a2c3c69bf4066396008efd8002be0790fee6c3 AS runtime-image

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all

WORKDIR /app

COPY --from=build-image /app/target/release/recert /usr/local/bin

ENTRYPOINT ["/usr/local/bin/recert"]
