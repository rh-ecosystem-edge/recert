# build stage
FROM registry.redhat.io/rhel9-4-els/rhel:9.4-1044 AS build-image
WORKDIR app
COPY . .

RUN subscription-manager register --org $(cat "/activation-key/org") --activationkey $(cat "/activation-key/activationkey") \
    && subscription-manager refresh \
    && subscription-manager repos --disable=* \
    --enable=rhel-9-for-x86_64-baseos-rpms \
    --enable=rhel-9-for-x86_64-appstream-rpms \
    --enable=codeready-builder-for-rhel-9-x86_64-rpms

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all \
    && subscription-manager unregister

RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4-149 AS runtime-image

RUN microdnf install -y 'subscription-manager' \
    && subscription-manager register --org $(cat "/activation-key/org") --activationkey $(cat "/activation-key/activationkey") \
    && subscription-manager refresh \
    && subscription-manager repos --disable=* \
    --enable=rhel-9-for-x86_64-baseos-rpms

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all \
    && subscription-manager unregister

WORKDIR app
COPY --from=build-image /app/target/release/recert /usr/local/bin
ENTRYPOINT ["/usr/local/bin/recert"]
