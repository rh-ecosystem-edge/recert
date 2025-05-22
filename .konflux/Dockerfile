# See README.Konflux.md before editing this Dockerfile

# build stage
FROM registry.redhat.io/rhel9-4-els/rhel:9.4@sha256:4988065272e68b8f1b3e14d1fd385df1f6170c4846ebd87f0af28faaaea773d8 AS build-image

WORKDIR /app

COPY . .

RUN PKGS="rust-toolset protobuf-compiler" \
    && dnf install -y $PKGS \
    && dnf clean all

RUN cargo build --release --bin recert

# runtime stage
FROM registry.redhat.io/rhel9-4-els/rhel-minimal:9.4@sha256:9577a9ed1707ba2a1a229559d188a015cf3b20b18e4b83541f427697d1c0b8df AS runtime-image

RUN PKGS="openssh-clients" \
    && microdnf install -y $PKGS \
    && microdnf clean all

WORKDIR /app

COPY --from=build-image /app/target/release/recert /usr/local/bin

ENTRYPOINT ["/usr/local/bin/recert"]
