# TCP Ping Prometheus Exporter

A high-performance TCP ping exporter for Prometheus written in Go. It measures latency (RTT), packet loss, and connection stability by sending active TCP probes to target servers. Supports client (prober), server (echo), and combined modes with adaptive timeout capabilities (RFC 6298).

## Metrics

The exporter exposes the following metrics at `/metrics` (default port 2112).

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `tcp_echo_sent_total` | Counter | `target`, `address` | Total echo requests sent on established connections (dial failures excluded). |
| `tcp_echo_received_total` | Counter | `target`, `address` | Total echo responses received and validated. |
| `tcp_echo_timeouts_total` | Counter | `target`, `address` | Total requests that timed out. Packet loss = timeouts / sent. |
| `tcp_echo_dropped_total` | Counter | `target`, `address` | Total established connections lost mid-probing. |
| `tcp_echo_connect_failures_total` | Counter | `target`, `address` | Total failed connection attempts (dial errors). Not counted in sent/timeout totals. |
| `tcp_echo_rtt_recent_seconds` | Summary | `target`, `address` | Sliding-window RTT percentiles over 10 min (p50, p90, p99). |
| `tcp_echo_rtt_recent_seconds_sum` | Summary | `target`, `address` | Sum of RTT over the 10 min window (divide by `_count` for mean). |
| `tcp_echo_rtt_recent_seconds_count` | Summary | `target`, `address` | Response count over the 10 min window. |
| `tcp_echo_last_rtt_seconds` | Gauge | `target`, `address` | Most recent RTT measurement. |
| `tcp_echo_connected` | Gauge | `target`, `address` | 1 = connected, 0 = disconnected/reconnecting. |
| `tcp_echo_estimated_timeout_seconds` | Gauge | `target`, `address` | Current adaptive RTO in use. |

## PromQL Examples

### Packet Loss Rate (%)

Dial failures are excluded from `sent_total`/`timeouts_total` — while the
client cannot connect, this ratio is undefined rather than pinned at 100%;
alert on `tcp_echo_connected == 0` or `rate(tcp_echo_connect_failures_total[5m]) > 0`
for that condition.

```
rate(tcp_echo_timeouts_total[5m]) / rate(tcp_echo_sent_total[5m]) * 100
```

### Average Latency (10-min Window)

The summary's `_sum`/`_count` span the same 10-minute sliding window as
the quantiles, so the mean matches the percentiles plotted alongside it.
Do NOT use `rate()` on them — they are not counters; the window resets
every 10 minutes.

```
tcp_echo_rtt_recent_seconds_sum / tcp_echo_rtt_recent_seconds_count
```

### Median / 90th / 99th Percentile Latency (Sliding Window)

```
tcp_echo_rtt_recent_seconds{quantile="0.5"}
tcp_echo_rtt_recent_seconds{quantile="0.9"}
tcp_echo_rtt_recent_seconds{quantile="0.99"}
```

### Detecting a Baseline Shift (latency change detection)

Compare the current 10-minute window against a longer baseline. Latency
drift on a long-running link shows up as the recent window diverging
from a 24h minimum:

```
tcp_echo_rtt_recent_seconds{quantile="0.5"}
  > min_over_time(tcp_echo_rtt_recent_seconds{quantile="0.5"}[24h]) * 1.5
```

Outages show up immediately in `tcp_echo_connected == 0`,
`rate(tcp_echo_timeouts_total[5m]) > 0`, and the adaptive RTO climbing
via `tcp_echo_estimated_timeout_seconds`.

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
| `-interval` | `500ms` | Client: probe interval (must stay well below server `-read-timeout`) |
| `-timeout` | `1s` | Client: Base/initial probe timeout |
| `-adaptive` | `true` | Enable adaptive RTO based on link quality |
| `-read-timeout` | `10s` | Server: idle read deadline per connection |
| `-metrics-user` | `""` | Basic auth username for /metrics (empty = disabled; env `TCP_PING_METRICS_USER`) |
| `-metrics-pass` | `""` | Basic auth password for /metrics (env `TCP_PING_METRICS_PASS`; prefer env over CLI to avoid `ps` exposure) |
| `-metrics-tls-cert` | `""` | TLS certificate file for /metrics (requires `-metrics-tls-key`) |
| `-metrics-tls-key` | `""` | TLS private key file for /metrics (requires `-metrics-tls-cert`) |
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

Use `-svc` to install/uninstall/start/stop/run. The tool records runtime flags at install time (excluding `-svc`, `-metrics-user`, and `-metrics-pass`). Metrics auth credentials are **not** persisted into the service configuration; set `TCP_PING_METRICS_USER` / `TCP_PING_METRICS_PASS` in the service environment instead (a warning is printed at install time).

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
main_test.go                — lifecycle race, auth/TLS flag validation tests
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
  validation_test.go        — LoadTargets, target parsing, Config validation
  server_test.go            — Server garbage handling, limits, shutdown
  client_test.go            — Robustness: loss, latency, corruption, spoofing, stalls, duplicates
  metrics_test.go           — Basic auth handler, metric seeding
  integration_test.go       — Multi-target, server dropout, stress (10 targets)
```

## Wire Protocol

24 bytes per probe:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Magic header `TCPPING\x00` |
| 8 | 8 | Sequence number (little-endian uint64) |
| 16 | 8 | Client timestamp (Unix ns, little-endian uint64) |

The server validates the magic header before echoing; invalid data closes the connection immediately. The client additionally requires the echoed timestamp to exactly match the value it sent — corrupted, replayed, or spoofed responses are discarded and counted as loss on timeout, protecting RTT samples from poisoning.

The server enforces a maximum of 1000 concurrent connections globally and 128 per remote IP; excess connections are dropped. Per-connection read deadlines (`-read-timeout`, default 10 s) and write deadlines (5 s) prevent resource starvation; transient accept errors back off exponentially. Client `-interval` must stay well below the server's read deadline or connections will be closed for idleness.

## Security

- The TCP echo server validates a magic header before echoing to prevent arbitrary payload reflection, and caps connections globally and per source IP.
- Echoed timestamps are validated exactly (see Wire Protocol), so off-path corruption and replays cannot fabricate RTT samples.
- The `/metrics` endpoint supports HTTP Basic Auth (`-metrics-user` / `-metrics-pass`) with constant-time comparison over hashed credentials. Both must be set together; the process refuses to start with only one.
- Prefer the `TCP_PING_METRICS_USER` / `TCP_PING_METRICS_PASS` environment variables over CLI flags — flag values are visible in `ps` to other local users.
- Basic Auth without TLS sends credentials as base64 on the wire; a startup warning is logged in that configuration. Use `-metrics-tls-cert` / `-metrics-tls-key` to serve `/metrics` over HTTPS.
- The wire protocol carries no sensitive data (sequence numbers and wall-clock timestamps only) and has no TLS — intended for internal network monitoring. Restrict access with a firewall on untrusted networks.
