# linux/amd64 variant. nodo builds it with --opt platform=linux/amd64 (from
# service.json), so both stages resolve to linux/amd64 images out of multi-arch
# indexes (rust:1.88.0-bookworm, debian:bookworm-slim), and `cargo build` with
# no --target emits a native x86_64 binary for them. Builder and runtime are
# both Debian 12 (glibc 2.36). Building it on a host of the other architecture
# needs a binfmt_misc handler for linux/amd64.

# Each FROM is pinned by the digest of its multi-arch index, so the same pin
# resolves to the image of the target architecture, and a tag that moves
# cannot change the image (and the service id) between two packs.
# Rust 1.88, not 1.86 as in the other children: Cargo.lock of this crate holds
# encoding_rs 0.8.42 and icu_* 2.3.0, which need rustc 1.88. With 1.86,
# `cargo build --locked` stops before it compiles anything.
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder
COPY service /sharefs-service
WORKDIR /sharefs-service
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
COPY --from=builder /sharefs-service/target/release/sharefs-service /sharefs-service
# Mount points for the shares this service inherits. The packer marks them as
# `guest` directories from service.json, so they have to exist in the image.
RUN mkdir -p /mnt/from-parent /mnt/readonly
