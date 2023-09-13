FROM rust:1 AS chef
# We only pay the installation cost once,
# it will be cached from the second build onwards
RUN cargo install cargo-chef
WORKDIR app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update
RUN apt-get install -y protobuf-compiler
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release --bin recert

FROM golang:1.19-bookworm as ouger-builder
COPY ./ouger $GOPATH/src
WORKDIR $GOPATH/src
RUN go build -buildvcs=false -o $GOPATH/bin/ouger

# We do not need the Rust toolchain to run the binary!
FROM debian:bookworm AS runtime
WORKDIR app
RUN apt-get update
RUN apt-get install -y openssl
COPY --from=ouger-builder /go/bin/ouger /usr/local/bin
COPY --from=builder /app/target/release/recert /usr/local/bin
ENTRYPOINT ["/usr/local/bin/recert"]
