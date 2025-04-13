FROM rust:latest AS builder
COPY service /tiny-service
WORKDIR tiny-service
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=builder /tiny-service/target/release/tiny-service /tiny-service

