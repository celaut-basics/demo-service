# linux/amd64 variant. nodo builds it with --opt platform=linux/amd64 (from
# service.json), so both stages resolve to linux/amd64 images out of multi-arch
# indexes (rust:1.86.0-bookworm, distroless/cc-debian12), and `cargo build` with no
# --target emits a native x86_64 binary for them. Builder and runtime are both
# Debian 12 (glibc 2.36). Building it on a host of the other architecture needs
# a binfmt_misc handler for linux/amd64.

FROM rust:1.86.0-bookworm AS builder
COPY service /heavy-service
WORKDIR /heavy-service
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /heavy-service/target/release/heavy-service /heavy-service

