FROM rust:1 AS chef
RUN cargo install cargo-chef
WORKDIR app

FROM chef AS planner
COPY Cargo.toml Cargo.lock .
COPY src/ src/
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN apt-get update
RUN apt-get install -y protobuf-compiler
RUN cargo chef cook --release --recipe-path recipe.json
COPY Cargo.toml Cargo.lock .
COPY src/ src/
RUN cargo build --release --bin recert

FROM docker.io/library/golang:1.19-bookworm as ouger-builder
COPY ./ouger $GOPATH/src
WORKDIR $GOPATH/src
RUN go build -buildvcs=false -o $GOPATH/bin/ouger_server cmd/server/ouger_server.go

FROM docker.io/library/debian:bookworm AS runtime
WORKDIR app
RUN apt-get update
RUN apt-get install -y openssl
COPY --from=ouger-builder /go/bin/ouger_server /usr/local/bin
COPY --from=builder /app/target/release/recert /usr/local/bin
ENTRYPOINT ["/usr/local/bin/recert"]
