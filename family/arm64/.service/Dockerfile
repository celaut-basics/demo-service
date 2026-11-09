# linux/arm64 variant of the family child. The busybox digest is a multi-arch index
# (linux/amd64 + linux/arm64), so the same pin resolves to the linux/arm64 image.
# The celaut binary is the static one of service-library v0.4.1, fetched by the
# sha256 of its release asset, as the verifier does.
FROM busybox:1.36.1-musl@sha256:3c6ae8008e2c2eedd141725c30b20d9c36b026eb796688f88205845ef17aa213
ADD --checksum=sha256:0173e4b9f33ee785176f68011995f29ceb4ea8d267ddbf7f8f1e24bcd08dd7e9 --chmod=755 \
    https://github.com/celaut-project/service-library/releases/download/v0.4.1/celaut-linux-arm64 \
    /usr/local/bin/celaut
COPY service /service
RUN chmod 755 /service/run.sh /service/stop.cgi
