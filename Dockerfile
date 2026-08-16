# GoReleaser builds the static binary (CGO_ENABLED=0) and stages it in the
# build context under per-platform dirs; TARGETPLATFORM (linux/amd64 or
# linux/arm64) selects the right one. This image only packages that binary.
# No CA certs or tzdata needed: the binary makes no TLS client calls
# (metrics TLS serves local cert files) and logs in UTC.
FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/link_ping_prometheus /link_ping_prometheus
USER 65532:65532
EXPOSE 4000/udp
EXPOSE 2112/tcp
ENTRYPOINT ["/link_ping_prometheus"]
