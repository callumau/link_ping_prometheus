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
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 4000:4000/udp -p 127.0.0.1:2112:2112 \
  ghcr.io/callumau/link_ping_prometheus:latest \
  -mode=server -listen=":4000" -allow=203.0.113.5 -metrics=":2112"
```

Client probing site B from site A (metrics only, no probe port needed):

```sh
docker run -d --name link-ping-client --restart=always \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 127.0.0.1:2112:2112 \
  ghcr.io/callumau/link_ping_prometheus:latest \
  -mode=client -target="203.0.113.10:4000" -source="sydney-dc" -metrics=":2112"
```

`-metrics=":2112"` is required in both examples: the binary's default bind is
`127.0.0.1:2112` inside the container, unreachable through a published port.
`-p 127.0.0.1:2112:2112` publishes it on the host's loopback only, so a local
scraper reaches it and nothing else does.

The container needs no capabilities and writes nothing but its own log file,
so run it with `--read-only --cap-drop=ALL --security-opt no-new-privileges`
(add a `-v` mounted directory for `-log-file` if you want a file sink;
otherwise stdout is the log).

If you publish the metrics port on a public interface (`-p 2112:2112`) instead,
the wildcard `-metrics=":2112"` is exposed to every host that can route to the
box — it carries the whole probe topology. Then require Basic auth
(`-metrics-user`/`-metrics-pass` plus `-metrics-tls-cert`/`-metrics-tls-key`, or
`-metrics-allow-insecure` to keep plaintext HTTP) or a firewall rule admitting
only the scraper.

A bridged container's probe datagrams are SNATed to the **host** address, so
the peer's `-allow` must list that host IP, not the container's — otherwise a
mesh of containers reads 100% loss. `--network host` avoids the NAT and keeps
the container's own identity on the wire.

All [flags](../README.md#usage) work as with the bare binary. File-based flags
(`-targets` JSON, TLS cert/key) need those files mounted into the scratch image,
e.g. `-v /etc/link-ping:/cfg:ro -targets=/cfg/targets.json`.
