# See README.Konflux.md before editing this Dockerfile

# build stage
FROM registry.redhat.io/rhel9-4-els/rhel:9.4@sha256:fb90aa79d76b673d7e765e55e0925598b8443c5d53c0facc2fe83f4b8636c8a1 AS build-image

WORKDIR /app

COPY . .

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all

RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4@sha256:52516cae98573355c14c6b43010d3839a086fd6e2d258707f033fed0ab34cae8 AS runtime-image

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all

WORKDIR /app

COPY --from=build-image /app/target/release/recert /usr/local/bin

ENTRYPOINT ["/usr/local/bin/recert"]
