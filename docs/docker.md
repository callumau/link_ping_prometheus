# Run with Docker

Multi-arch container images (`linux/amd64`, `linux/arm64`) are published to
[GitHub Container Registry](https://github.com/callumau/link_ping_prometheus/pkgs/container/link_ping_prometheus)
on every release tag:

```sh
docker pull ghcr.io/callumau/link_ping_prometheus:latest
```

The image runs as an unprivileged user (UID 65532). Server mode listens on UDP
4000; the metrics endpoint is served on TCP 2112.

Echo server at the remote site (fail-closed: `-allow` is required):

```sh
docker run -d --name link-ping-server --restart=always \
  -p 4000:4000/udp -p 2112:2112 \
  ghcr.io/callumau/link_ping_prometheus:latest \
  -mode=server -listen=":4000" -allow=203.0.113.5 -metrics=":2112"
```

Client probing site B from site A (metrics only, no probe port needed):

```sh
docker run -d --name link-ping-client --restart=always \
  -p 2112:2112 \
  ghcr.io/callumau/link_ping_prometheus:latest \
  -mode=client -target="203.0.113.10:4000" -source="sydney-dc" -metrics=":2112"
```

`-metrics=":2112"` is required in both examples: the binary's default bind is
`127.0.0.1:2112`, unreachable through the container's published `-p 2112:2112`
port.

All [flags](../README.md#usage) work as with the bare binary. File-based flags
(`-targets` JSON, TLS cert/key) need those files mounted into the scratch image,
e.g. `-v /etc/link-ping:/cfg:ro -targets=/cfg/targets.json`.
