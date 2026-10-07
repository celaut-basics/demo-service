# linux/amd64 variant. nodo builds it with --opt platform=linux/amd64 (from
# service.json), so both stages resolve to linux/amd64 images out of multi-arch
# indexes (rust:1.86.0-bookworm, debian:bookworm-slim), and `cargo build` with
# no --target emits a native x86_64 binary for them. Builder and runtime are
# both Debian 12 (glibc 2.36). Building it on a host of the other architecture
# needs a binfmt_misc handler for linux/amd64.

# Each FROM is pinned by the digest of its multi-arch index, so the same pin
# resolves to the image of the target architecture, and a tag that moves
# cannot change the image (and the service id) between two packs.
FROM rust:1.86.0-bookworm@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS builder
COPY service /ping-service
WORKDIR /ping-service
RUN cargo build --release --locked

# Not distroless: dns.rs writes /etc/resolv.conf at start, so the runtime
# keeps a plain Debian /etc. Nothing is installed on top of it. TLS is rustls
# with its own root store (Cargo.toml), and the binary links only libc,
# libm and libgcc_s, so the image needs no OpenSSL and no CA bundle.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
COPY --from=builder /ping-service/target/release/ping-service /ping-service
