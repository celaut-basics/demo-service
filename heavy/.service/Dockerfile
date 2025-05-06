FROM rust:latest AS builder
COPY service /heavy-service
WORKDIR heavy-service
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=builder /heavy-service/target/release/heavy-service /heavy-service

