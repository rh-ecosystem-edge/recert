# The rust version is pinned to prevent unexpected breakages due to rust changes.
FROM rust:1.87 AS chef
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock .
COPY src/ src/
COPY vendor/ vendor/
COPY .cargo/ .cargo/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN apt-get update
RUN apt-get install -y protobuf-compiler
COPY vendor/ vendor/
RUN cargo chef cook --release --recipe-path recipe.json
COPY Cargo.toml Cargo.lock .
COPY .cargo/ .cargo/
COPY src/ src/
COPY build.rs build.rs
RUN cargo build --release --bin recert

FROM docker.io/library/debian:trixie AS runtime
WORKDIR /app
RUN apt-get update
RUN apt-get install -y openssl openssh-client
COPY --from=builder /app/target/release/recert /usr/local/bin
ENTRYPOINT ["/usr/local/bin/recert"]
