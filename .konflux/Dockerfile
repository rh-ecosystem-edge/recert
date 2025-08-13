# See README.Konflux.md before editing this Dockerfile

# build stage
FROM registry.redhat.io/rhel9-4-els/rhel:9.4@sha256:00e433b9ad6b154ec6e68fc8afb76e4d4771b17bc806074ceb74ef0ba0e380de AS build-image

WORKDIR /app

COPY . .

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all

RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4@sha256:83865568f25a483dcd7f84831dd0de8cef393943515bbb1a7d3a93b72886dbf8 AS runtime-image

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all

WORKDIR /app

COPY --from=build-image /app/target/release/recert /usr/local/bin

ENTRYPOINT ["/usr/local/bin/recert"]
