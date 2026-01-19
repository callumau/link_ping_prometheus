# tcp_ping_prometheus

- RTT histogram and last RTT (tcp_echo_rtt_seconds{target="name"}, tcp_echo_last_rtt_seconds{target="name"}),
- Sent/received counters and timeouts (tcp_echo_sent_total{target="name"}, tcp_echo_received_total{target="name"}, tcp_echo_timeouts_total{target="name"}),
- Connection status (tcp_echo_connected{target="name"}),
- Adaptive RTO estimation (tcp_echo_estimated_timeout_seconds{target="name"}).

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

Test
-----

Run the test suite:

```sh
go test -v ./...
```


Release binaries for Linux, macOS (darwin) and Windows - [Latest Release](https://github.com/callumau/tcp_ping_prometheus/releases/latest)

Usage
-----
- -mode: server | client | both (default "server")
- -listen: server listen address (default ":4000")
- -target: client target address (default ":4000") - use -targets for multiple
- -targets: JSON file with list of targets (client)
- -metrics: HTTP address for Prometheus /metrics (default ":2112")
- -interval: Base probe interval (min interval if adaptive) (default 500ms)
- -timeout: Base/Initial timeout (default 1s)
- -adaptive: Enable adaptive timeout/interval based on link quality (default true)
- -json-logs: Log in JSON format instead of text
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

Service
-------

### Windows

Use the `-svc` flag to install/uninstall/start/stop/run the service. When installing, the tool records the runtime flags to ensure the service starts with the same configuration.

```
tcp-echo-metrics.exe -mode=both -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113" -window=100 -svc=install
```

### Linux

To run as a systemd service, create a file at `/etc/systemd/system/tcp-echo-metrics.service`:

```ini
[Unit]
Description=TCP Echo Metrics
After=network.target

[Service]
ExecStart=/usr/local/bin/tcp-echo-metrics -mode=server -listen=":4000" -metrics=":2112"
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

**Note regarding targets.json**: If running in client or both mode, ensure you provide the **absolute path** to the targets file in the `-targets` flag (e.g., `-targets=/etc/tcp-echo-metrics/targets.json`) and that the designated `User` has read permissions for the file.

Reload systemd and start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now tcp-echo-metrics
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
- Wire format: 24 bytes per probe (8-byte magic header "TCPPING\x00", 8-byte sequence, 8-byte Unix-ns timestamp). See [tcp_ping_prometheus.go](tcp_ping_prometheus.go).
- Histogram buckets chosen for 100µs .. ~2s RTTs.
- The release workflow produces binaries for linux, windows, and darwin and packages each artifact (see [.github/workflows/new-release-build.yml](.github/workflows/new-release-build.yml)).
- Security: This tool is intended for internal network monitoring. The TCP echo server validates a magic header ("TCPPING\x00") before echoing data to prevent arbitrary payload reflection, but it is still recommended to restrict access to trusted networks. The metrics endpoint serves data without authentication; protect it accordingly.

