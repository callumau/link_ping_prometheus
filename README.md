# tcp_ping_prometheus

This program can run as a TCP echo server, a client that continuously probes a server, or both. It records:
- RTT histogram and last RTT ([tcp_echo_rtt_seconds], [tcp_echo_last_rtt_seconds]),
- Sent/received counters and timeouts ([tcp_echo_sent_total], [tcp_echo_received_total], [tcp_echo_timeouts_total]),
- Connection/connect metrics and a sliding-window loss percentage gauge ([tcp_echo_connects_total], [tcp_echo_connected], [tcp_echo_loss_percent]).

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

Release binaries for Linux, macOS (darwin) and Windows - [Releases](.github/releases)

Usage
-----
Flags:

- -mode: server | client | both (default "server")
- -listen: server listen address (default ":4000")
- -target: client target address (default ":4000")
- -metrics: HTTP address for Prometheus metrics (default ":2112")
- -interval: probe interval (default 200ms)
- -timeout: per-probe timeout (default 800ms)
- -window: sliding window size for loss percentage (default 100)
- -svc: service action: install | uninstall | start | stop | run (uses kardianos/service on Windows)

Examples (also in [example_queries.txt](example_queries.txt)):

Client:
```
./tcp-echo-metrics -mode=client -target="192.168.1.71:4000" -interval=10ms -timeout=20ms -metrics=":2113" -window=100
```

Server:
```
./tcp-echo-metrics -mode=server -listen=":4000" -metrics=":2112"
```

Both:
```
./tcp-echo-metrics -mode=both -target="192.168.1.71:4000" -interval=10ms -timeout=20ms -metrics=":2113" -window=100
```

Service (Windows)
-----------------
Use the `-svc` flag to install/uninstall/start/stop/run the service. When installing, the tool records the runtime flags to ensure the service starts with the same configuration.

```
tcp-echo-metrics.exe -mode=both -target="192.168.1.71:4000" -interval=10ms -timeout=20ms -metrics=":2113" -window=100 -svc=install
```

Metrics
-------
The exporter serves Prometheus metrics at /metrics on the address given by `-metrics` (default :2112). 

Prebuilt Grafana Dashboard [grafana-dashboard.json](grafana-dashboard.json).

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

