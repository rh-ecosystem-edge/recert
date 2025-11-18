# See README.Konflux.md before editing this Dockerfile
ARG BUILDER_IMAGE=registry.access.redhat.com/ubi9/ubi:latest
ARG RUNTIME_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal:latest

# build stage
FROM ${BUILDER_IMAGE} AS builder-image

WORKDIR /app

COPY . .

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all

RUN cargo build --release --bin recert

# runtime stage
FROM ${RUNTIME_IMAGE} AS runtime-image

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all

WORKDIR /app

COPY --from=builder-image /app/target/release/recert /usr/local/bin

ENTRYPOINT ["/usr/local/bin/recert"]
