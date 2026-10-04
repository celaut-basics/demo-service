# linux/arm64 variant. nodo builds it with --opt platform=linux/arm64 (from
# service.json), so both stages resolve to linux/arm64 images out of multi-arch
# indexes (rust:1.86.0-bookworm, debian:bookworm-slim), and `cargo build` with
# no --target emits a native aarch64 binary for them. Builder and runtime are
# both Debian 12 (glibc 2.36). Building it on a host of the other architecture
# needs a binfmt_misc handler for linux/arm64.

FROM rust:1.86.0-bookworm AS builder
COPY service /ping-service
WORKDIR ping-service
RUN cargo build --release --locked

# FROM gcr.io/distroless/cc
# COPY --from=builder /ping-service/target/release/ping-service /ping-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /ping-service/target/release/ping-service /ping-service