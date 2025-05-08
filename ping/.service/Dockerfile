FROM rust:latest AS builder
COPY service /ping-service
WORKDIR ping-service
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=builder /ping-service/target/release/ping-service /ping-service

