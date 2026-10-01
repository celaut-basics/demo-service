# Pinned by digest, like every other image in this repo: the scores a node files
# are only comparable with another node's if both ran the very same busybox, and
# the service id (a content hash) is what makes that checkable. The digest is the
# multi-arch index, so packing for linux/amd64 or linux/arm64 picks the matching
# image from the same pin.
FROM busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
COPY service /benchmark
RUN chmod +x /benchmark/serve /benchmark/bench.sh /benchmark/www/cgi-bin/benchmark /benchmark/www/cgi-bin/whoami
