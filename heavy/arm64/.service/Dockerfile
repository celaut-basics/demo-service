# linux/arm64 variant. nodo builds it with --opt platform=linux/arm64 (from
# service.json), so both stages resolve to linux/arm64 images out of multi-arch
# indexes (rust:1.86.0-bookworm, distroless/cc), and `cargo build` with no
# --target emits a native aarch64 binary for them. Builder and runtime are both
# Debian 12 (glibc 2.36). Building it on a host of the other architecture needs
# a binfmt_misc handler for linux/arm64.

FROM rust:1.86.0-bookworm AS builder
COPY service /heavy-service
WORKDIR heavy-service
RUN cargo build --release --locked

FROM gcr.io/distroless/cc
COPY --from=builder /heavy-service/target/release/heavy-service /heavy-service

