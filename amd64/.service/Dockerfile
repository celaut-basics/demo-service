# linux/amd64 variant. nodo builds it with --opt platform=linux/amd64 (from
# service.json). The python:3.11 digest below is a multi-arch index (linux/amd64
# + linux/arm64), so the same pin resolves to the linux/amd64 image. The only
# native wheel pulled in, grpcio==1.56.0 (via bee-rpc), ships cp311 manylinux
# wheels for x86_64 and aarch64, and protobuf does too, so nothing is compiled
# during the build.

# Every dependency is pinned. This service is content-addressed: two packs of the
# same source tree must produce the same image, so a moving tag or an unpinned
# `git+` install (which resolves to whatever master happened to be that day)
# silently breaks reproducibility — and makes any bug observed in a running
# instance impossible to trace back to a specific library revision.
FROM python:3.11@sha256:7bd2bbe2112147be4dbe68802d60eee6c5e46042f621ffdf2102264aeeba8716
RUN apt-get update --fix-missing && \
    pip3 install --no-cache-dir \
        requests==2.32.3 \
        Flask==3.0.3 \
        git+https://github.com/bee-rpc-protocol/celaut-service-libraries
COPY service /service
RUN chmod +x /service/app.py
