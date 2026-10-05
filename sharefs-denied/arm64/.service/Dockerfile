# linux/arm64 variant. nodo builds it with --opt platform=linux/arm64 (from
# service.json), so both stages resolve to linux/arm64 images out of multi-arch
# indexes (rust:1.86.0-bookworm, debian:bookworm-slim), and `cargo build` with
# no --target emits a native aarch64 binary for them. Builder and runtime are
# both Debian 12 (glibc 2.36). Building it on a host of the other architecture
# needs a binfmt_misc handler for linux/arm64.

FROM rust:1.86.0-bookworm AS builder
COPY service /sharefs-denied-service
WORKDIR sharefs-denied-service
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=builder /sharefs-denied-service/target/release/sharefs-denied-service /sharefs-denied-service
# Mount point for the share this service declares but was never granted.
RUN mkdir -p /mnt/not-granted
