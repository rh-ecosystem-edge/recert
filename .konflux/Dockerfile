# See README.Konflux.md before editing this Dockerfile

# build stage
FROM registry.redhat.io/rhel9-6-els/rhel:9.6@sha256:bb69b92eef84674d85d899ae5e46057f70b73ce5805004c237c047eb77390636 AS build-image

WORKDIR /app

COPY . .

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all

RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-6-els/rhel-minimal:9.6@sha256:2bdf19e0877fdbb0696330159ed72a12deef8a60eed819c4e2fc0064147b39df AS runtime-image

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all

WORKDIR /app

COPY --from=build-image /app/target/release/recert /usr/local/bin

ENTRYPOINT ["/usr/local/bin/recert"]
