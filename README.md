# tcp_ping_prometheus

This program can run as a TCP echo server, a client that continuously probes one or more servers, or both. It records:
- RTT histogram and last RTT (tcp_echo_rtt_seconds{target="name"}, tcp_echo_last_rtt_seconds{target="name"}),
- Sent/received counters and timeouts (tcp_echo_sent_total{target="name"}, tcp_echo_received_total{target="name"}, tcp_echo_timeouts_total{target="name"}),
- Connection/connect metrics and a sliding-window loss percentage gauge (tcp_echo_connects_total{target="name"}, tcp_echo_connected{target="name"}, tcp_echo_loss_percent{target="name"}).

See the implementation in [tcp_ping_prometheus.go](tcp_ping_prometheus.go).

Build
-----
Build locally:

```sh
go build -o ./build/tcp-echo-metrics .
```

Cross-compile for Windows (example):

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o build/tcp-echo-metrics.exe .
```

Download
-----

Release binaries for Linux, macOS (darwin) and Windows - [Latest Release](https://github.com/callumau/tcp_ping_prometheus/releases/latest)

Usage
-----
Flags:

- -mode: server | client | both (default "server")
- -listen: server listen address (default ":4000")
- -target: client target address (default ":4000") - use -targets for multiple
- -targets: JSON file with list of targets (client)
- -metrics: HTTP address for Prometheus /metrics (default ":2112")
- -interval: probe interval (default 200ms)
- -timeout: per-probe timeout (default 800ms)
- -window: sliding window size for loss percentage (default 100)
- -svc: service action: install | uninstall | start | stop | run (uses kardianos/service on Windows)

JSON Targets Format:

The -targets flag expects a JSON file containing an array of objects, each with "name" and "address" fields.

Example targets.json:

```json
[
  {"name": "server1", "address": "192.168.1.10:4000"},
  {"name": "server2", "address": "192.168.1.11:4000"}
]
```

Examples (also in [example_queries.txt](example_queries.txt)):

Client (single target):
```
./tcp-echo-metrics -mode=client -target="192.168.1.71:4000" -interval=10ms -timeout=20ms -metrics=":2113" -window=100
```

Client (multiple targets):
```
./tcp-echo-metrics -mode=client -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113" -window=100
```

Server:
```
./tcp-echo-metrics -mode=server -listen=":4000" -metrics=":2112"
```

Both:
```
./tcp-echo-metrics -mode=both -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113" -window=100
```

Service (Windows)
-----------------
Use the `-svc` flag to install/uninstall/start/stop/run the service. When installing, the tool records the runtime flags to ensure the service starts with the same configuration.

```
tcp-echo-metrics.exe -mode=both -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113" -window=100 -svc=install
```

Metrics
-------
The exporter serves Prometheus metrics at /metrics on the address given by `-metrics` (default :2112). 

Prebuilt Grafana Dashboard [grafana-dashboard.json](grafana-dashboard.json).

[![Grafana dashboard screenshot](.docs/screenshot01.png)](.docs/screenshot01.png)

Key functions and types
-----------------------
- [`runClient`](tcp_ping_prometheus.go) — main client loop that reconnects and probes.
- [`runServer`](tcp_ping_prometheus.go) — TCP echo server.
- [`pump`](tcp_ping_prometheus.go) — per-connection probe send/receive/timeout handling.
- [`lossTracker`](tcp_ping_prometheus.go) — sliding-window loss tracker that updates the gauge.

Notes
-----
- Wire format: 16 bytes per probe (8-byte sequence, 8-byte Unix-ns timestamp). See [tcp_ping_prometheus.go](tcp_ping_prometheus.go).
- Histogram buckets chosen for 100µs .. ~2s RTTs.
- The release workflow produces binaries for linux, windows, and darwin and packages each artifact (see [.github/workflows/new-release-build.yml](.github/workflows/new-release-build.yml)).
- Security: This tool is intended for internal network monitoring. The TCP echo server accepts connections from any source and echoes back data, which could be exploited if exposed publicly. Ensure the server is not accessible from untrusted networks. The metrics endpoint serves data without authentication; protect it accordingly.

