# TCP Ping Prometheus Exporter

A high-performance TCP ping exporter for Prometheus written in Go. It measures latency (RTT), packet loss, and connection stability by sending active TCP probes to target servers. Supports client (prober), server (echo), and combined modes with adaptive timeout capabilities (RFC 6298).

## Metrics

The exporter exposes the following metrics at `/metrics` (default port 2112).

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `tcp_echo_sent_total` | Counter | `target`, `address` | Total echo requests sent. |
| `tcp_echo_received_total` | Counter | `target`, `address` | Total echo responses received. |
| `tcp_echo_timeouts_total` | Counter | `target`, `address` | Total requests that timed out. Packet loss = timeouts / sent. |
| `tcp_echo_dropped_total` | Counter | `target`, `address` | Total connection drops/failures. |
| `tcp_echo_rtt_seconds` | Histogram | `target`, `address` | Histogram of RTT in seconds (buckets: 500 µs – ~8 s). |
| `tcp_echo_rtt_recent_seconds` | Summary | `target`, `address` | Sliding-window RTT percentiles over 10 min (p50, p90, p99). |
| `tcp_echo_last_rtt_seconds` | Gauge | `target`, `address` | Most recent RTT measurement. |
| `tcp_echo_connected` | Gauge | `target`, `address` | 1 = connected, 0 = disconnected/reconnecting. |
| `tcp_echo_estimated_timeout_seconds` | Gauge | `target`, `address` | Current adaptive RTO in use. |

## PromQL Examples

### Packet Loss Rate (%)

```
rate(tcp_echo_timeouts_total[5m]) / rate(tcp_echo_sent_total[5m]) * 100
```

### Average Latency (RTT)

```
rate(tcp_echo_rtt_seconds_sum[5m]) / rate(tcp_echo_rtt_seconds_count[5m])
```

### 99th Percentile Latency (Histogram)

```
histogram_quantile(0.99, rate(tcp_echo_rtt_seconds_bucket[5m]))
```

### 99th Percentile Latency (Sliding Window)

```
tcp_echo_rtt_recent_seconds{quantile="0.99"}
```

### Connection Status

```
tcp_echo_connected
```

## Build

```sh
go build -o ./build/tcp_ping_prometheus .
```

Cross-compile for Windows:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o build/tcp_ping_prometheus.exe .
```

## Test

```sh
go test -count=1 ./test/...
```

Release binaries for Linux, macOS, Windows at [Latest Release](https://github.com/callumau/tcp_ping_prometheus/releases/latest).

## Usage

```
tcp_ping_prometheus -mode=<mode> [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-mode` | `server` | Operation mode: `server`, `client`, `both` |
| `-listen` | `:4000` | Server listen address |
| `-target` | `""` | Client: single target `host:port` |
| `-targets` | `""` | Client: path to JSON targets file |
| `-metrics` | `:2112` | Prometheus metrics HTTP listen address |
| `-interval` | `500ms` | Base probe interval (minimum when adaptive) |
| `-timeout` | `1s` | Base/initial probe timeout |
| `-adaptive` | `true` | Enable adaptive RTO based on link quality |
| `-metrics-user` | `""` | Basic auth username for /metrics (empty = disabled) |
| `-metrics-pass` | `""` | Basic auth password for /metrics |
| `-json-logs` | `false` | Output logs in JSON format |
| `-svc` | `""` | Windows service action: `install`, `uninstall`, `start`, `stop`, `run` |

### Targets File

JSON file with an array of `{"name": "...", "address": "host:port"}` objects:

```json
[
  {"name": "server1", "address": "192.168.1.10:4000"},
  {"name": "server2", "address": "192.168.1.11:4000"}
]
```

Max 1000 targets, max file size 1 MB.

### Examples

Client (single target):

```sh
./tcp_ping_prometheus -mode=client -target="192.168.1.71:4000" -interval=10ms -timeout=20ms -metrics=":2113"
```

Client (multiple targets):

```sh
./tcp_ping_prometheus -mode=client -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113"
```

Server:

```sh
./tcp_ping_prometheus -mode=server -listen=":4000" -metrics=":2112"
```

Both:

```sh
./tcp_ping_prometheus -mode=both -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113"
```

## Service

### Windows

Use `-svc` to install/uninstall/start/stop/run. The tool records runtime flags at install time (excluding `-svc` and `-metrics-pass`).

```
tcp_ping_prometheus.exe -mode=both -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113" -svc=install
```

### Linux (systemd)

Create `/etc/systemd/system/tcp_ping_prometheus.service`:

```ini
[Unit]
Description=TCP Ping Prometheus
After=network.target

[Service]
ExecStart=/usr/local/bin/tcp_ping_prometheus -mode=server -listen=":4000" -metrics=":2112"
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

Note: In client/both mode, use an absolute path for `-targets` (e.g., `-targets=/etc/tcp_ping_prometheus/targets.json`).

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now tcp_ping_prometheus
```

## Grafana Dashboard

Prebuilt dashboard at [grafana-dashboard.json](grafana-dashboard.json).

[![Grafana dashboard screenshot](.docs/screenshot01.png)](.docs/screenshot01.png)

## Code Structure

```
main.go                     — CLI wrapper, flag parsing, service lifecycle
internal/prober/
  prober.go                 — Config, protocol constants
  adaptive.go               — RFC 6298 RTO estimation (AdaptiveStats)
  client.go                 — Target, LoadTargets, RunClient, probe loop
  server.go                 — RunServer, ServeListener, connection handler
  metrics.go                — Prometheus metric vars, InitMetrics, MetricsAuth
  validate.go               — Target address validation (ValidateTarget)
  pool.go                   — sync.Pool for probe buffer reuse
test/
  helpers_test.go           — Test utilities (metric inspectors, echo server)
  adaptive_test.go          — AdaptiveStats logic and jitter adaptation
  validation_test.go        — LoadTargets and target parsing
  server_test.go            — Server garbage handling, header enforcement
  client_test.go            — Robustness: packet loss, latency, corruption, stalls, duplicates
  integration_test.go       — Multi-target, server dropout, stress (10 targets)
```

## Wire Protocol

24 bytes per probe:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Magic header `TCPPING\x00` |
| 8 | 8 | Sequence number (little-endian uint64) |
| 16 | 8 | Client timestamp (Unix ns, little-endian uint64) |

The server validates the magic header before echoing; invalid data closes the connection immediately. The server enforces a maximum of 1000 concurrent connections; excess connections are dropped. Read deadlines (10 s) and write deadlines (5 s) prevent resource starvation.

## Security

- The TCP echo server validates a magic header before echoing to prevent arbitrary payload reflection.
- The `/metrics` endpoint can be protected with HTTP Basic Auth (`-metrics-user` / `-metrics-pass`) using constant-time comparison.
- No TLS — this tool is intended for internal network monitoring. The wire protocol carries no sensitive data (sequence numbers and wall-clock timestamps only). Restrict access with a firewall for untrusted networks.
