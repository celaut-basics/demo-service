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
# bee-rpc and celaut-service-libraries (node_controller) are pinned by commit.
# The bee-rpc commit is the one of its v0.0.1 tag, which is what nodo itself
# installs (bash/requirements.txt), so both ends speak the same bee-rpc.
# celaut-service-libraries declares bee-rpc as an unpinned `git+` requirement,
# so it is installed with --no-deps after the pinned bee-rpc: otherwise pip
# would fetch bee-rpc master again. grpcio and protobuf are the versions a
# current nodo install runs with. The second group pins what Flask and
# requests pull in, so that no transitive package floats either.
FROM python:3.11@sha256:7bd2bbe2112147be4dbe68802d60eee6c5e46042f621ffdf2102264aeeba8716
RUN pip3 install --no-cache-dir \
        requests==2.32.3 \
        Flask==3.0.3 \
        grpcio==1.56.0 \
        protobuf==7.36.2 \
        Werkzeug==3.1.9 Jinja2==3.1.6 MarkupSafe==3.0.4 itsdangerous==2.2.0 \
        click==8.5.0 blinker==1.9.0 urllib3==2.8.0 idna==3.20 \
        charset-normalizer==3.5.2 certifi==2026.7.22 \
        "bee-rpc @ git+https://github.com/bee-rpc-protocol/bee-rpc-over-grpc-py@8049fd86261c0d85445e6c27d363e0c82d5b2958" && \
    pip3 install --no-cache-dir --no-deps \
        "celaut_libs @ git+https://github.com/bee-rpc-protocol/celaut-service-libraries@23459eea47351c75cffffa9318049aad8810ea75"
COPY service /service
RUN chmod +x /service/app.py
# Directories this service exports to its children. The packer marks them as
# `shared` from service.json, so they have to exist in the image. The share
# lives outside the rootfs, and its bytes are charged to this service's disk.
RUN mkdir -p /shared /shared-ro
