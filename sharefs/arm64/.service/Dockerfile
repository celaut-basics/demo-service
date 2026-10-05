# linux/arm64 variant. nodo builds it with --opt platform=linux/arm64 (from
# service.json), so both stages resolve to linux/arm64 images out of multi-arch
# indexes (rust:1.86.0-bookworm, debian:bookworm-slim), and `cargo build` with
# no --target emits a native aarch64 binary for them. Builder and runtime are
# both Debian 12 (glibc 2.36). Building it on a host of the other architecture
# needs a binfmt_misc handler for linux/arm64.

FROM rust:1.86.0-bookworm AS builder
COPY service /sharefs-service
WORKDIR /sharefs-service
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=builder /sharefs-service/target/release/sharefs-service /sharefs-service
# Mount points for the shares this service inherits. The packer marks them as
# `guest` directories from service.json, so they have to exist in the image.
RUN mkdir -p /mnt/from-parent /mnt/readonly
