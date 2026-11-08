# linux/arm64 variant. nodo builds it with --opt platform=linux/arm64 (from
# service.json). The python:3.11 digest below is a multi-arch index (linux/amd64
# + linux/arm64), so the same pin resolves to the linux/arm64 image. The only
# native wheels, grpcio==1.56.0 and protobuf==7.36.2, ship cp311/abi3
# manylinux wheels for x86_64 and aarch64, so nothing is compiled during the
# build.

# Every dependency is pinned. This service is content-addressed: two packs of the
# same source tree must produce the same image, so a moving tag or an unpinned
# `git+` install (which resolves to whatever master happened to be that day)
# silently breaks reproducibility, and makes any bug observed in a running
# instance impossible to trace back to a specific library revision.
#
# bee-rpc is pinned by commit. It is the one of its v0.0.3 tag, which is what nodo itself
# installs (bash/requirements.txt), so both ends speak the same bee-rpc. nodo_gateway.py
# uses it for the calls that the `celaut` command does not make. grpcio and protobuf are
# pinned so they cannot float; nodo's bash/requirements.txt pins bee-rpc only. The second
# group pins what Flask and requests pull in. cryptography (and what it pulls in)
# checks the Ed25519 signature of the node's balance statements; it ships abi3
# manylinux wheels for x86_64 and aarch64.
#
# The children are started, stopped and observed with `celaut` (celaut-project/service-library,
# v0.4.1): one static binary per architecture, fetched from the release by its sha256, so the
# build stays reproducible and a changed asset fails the build. The Python library of Celaut
# services (celaut-service-libraries, node_controller) is no longer installed.
FROM python:3.11@sha256:7bd2bbe2112147be4dbe68802d60eee6c5e46042f621ffdf2102264aeeba8716
RUN pip3 install --no-cache-dir \
        requests==2.32.3 \
        Flask==3.0.3 \
        grpcio==1.56.0 \
        protobuf==7.36.2 \
        Werkzeug==3.1.9 Jinja2==3.1.6 MarkupSafe==3.0.4 itsdangerous==2.2.0 \
        click==8.5.0 blinker==1.9.0 urllib3==2.8.0 idna==3.20 \
        charset-normalizer==3.5.2 certifi==2026.7.22 \
        cryptography==50.0.2 cffi==2.1.1 pycparser==3.12 \
        "bee-rpc @ git+https://github.com/bee-rpc-protocol/bee-rpc-over-grpc-py@b250bcaca191209560be7b41b872d996e8c010d2"
ADD --checksum=sha256:0173e4b9f33ee785176f68011995f29ceb4ea8d267ddbf7f8f1e24bcd08dd7e9 --chmod=755 \
    https://github.com/celaut-project/service-library/releases/download/v0.4.1/celaut-linux-arm64 \
    /usr/local/bin/celaut
COPY service /service
RUN chmod +x /service/app.py
# Directories this service exports to its children. The packer marks them as
# `shared` from service.json, so they have to exist in the image. The share
# lives outside the rootfs, and its bytes are charged to this service's disk.
RUN mkdir -p /shared /shared-ro
