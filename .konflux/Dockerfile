# build stage
FROM registry.redhat.io/rhel9-4-els/rhel:9.4-1044 AS build-image
WORKDIR app
COPY . .

RUN subscription-manager register --org $(cat "/activation-key/org") --activationkey $(cat "/activation-key/activationkey") \
    && subscription-manager repos --disable=*eus*
RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all
RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4-149 AS runtime-image

RUN microdnf install -y 'openssh-clients' \
    && microdnf clean all

WORKDIR app
COPY --from=build-image /app/target/release/recert /usr/local/bin
ENTRYPOINT ["/usr/local/bin/recert"]
