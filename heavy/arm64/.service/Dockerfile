# linux/arm64 variant. nodo builds it with --opt platform=linux/arm64 (from
# service.json), so both stages resolve to linux/arm64 images out of multi-arch
# indexes (rust:1.86.0-bookworm, distroless/cc-debian12), and `cargo build` with no
# --target emits a native aarch64 binary for them. Builder and runtime are both
# Debian 12 (glibc 2.36). Building it on a host of the other architecture needs
# a binfmt_misc handler for linux/arm64.

# Each FROM is pinned by the digest of its multi-arch index, so the same pin
# resolves to the image of the target architecture, and a tag that moves
# cannot change the image (and the service id) between two packs.
FROM rust:1.86.0-bookworm@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS builder
COPY service /heavy-service
WORKDIR /heavy-service
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa
COPY --from=builder /heavy-service/target/release/heavy-service /heavy-service

