FROM rust:1.86.0-bookworm AS builder
COPY service /ping-service
WORKDIR ping-service
RUN cargo build --release

# FROM gcr.io/distroless/cc
# COPY --from=builder /ping-service/target/release/ping-service /ping-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev dnsutils && rm -rf /var/lib/apt/lists/*
COPY --from=builder /ping-service/target/release/ping-service /ping-service