# Link Monitor (TCP Ping Prometheus Exporter)

A high-performance **site-to-site link monitor** for Prometheus written
in Go. It measures latency (RTT), packet loss, jitter, and connection
stability between two sites by sending active TCP probes across the
link, with adaptive timeout capabilities (RFC 6298).

## Typical Deployment: Site A ↔ Site B

1. **Remote site (B):** run the echo server.
   `./tcp_ping_prometheus -mode=server -listen=":4000" -metrics=":2112"`
2. **Local site (A):** run the client, targeting site B's address, and
   tag every metric with the local topology label:
   `./tcp_ping_prometheus -mode=client -target="203.0.113.10:4000" -source="sydney-dc" -metrics=":2112"`
3. Scrape both `/metrics` endpoints into Prometheus (or forward via
   Grafana Alloy, see below) and open the bundled dashboard.

Each configured target is one monitored link. The dashboard gives the
per-link picture: `link_up` status, packet loss (rate-derived), RTT
percentiles (p50/p90/p99), jitter, adaptive RTO, and throughput
counters.

## Metrics

The exporter exposes the following metrics at `/metrics` (default port 2112).

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `link_up` | Gauge | `source`, `target`, `address` | 1 = connected, 0 = disconnected/reconnecting. |
| `link_probes_sent_total` | Counter | `source`, `target`, `address` | Total probes sent on established connections (dial failures excluded). |
| `link_probes_timed_out_total` | Counter | `source`, `target`, `address` | Total probes that timed out. |
| `link_probes_inflight` | Gauge | `source`, `target`, `address` | Current number of probes sent but waiting for a response or timeout. Grows during stalls — deadlock/detached-peer detection. |
| `link_flaps_total` | Counter | `source`, `target`, `address` | Total link flaps: established connections lost mid-probing. Rate = link instability per window. |
| `link_connect_failures_total` | Counter | `source`, `target`, `address` | Total failed connection attempts (dial errors). Not counted in sent/timeout totals. |
| `link_rtt_seconds` | Histogram | `source`, `target`, `address` | RTT histogram with explicit buckets `{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}` s plus native histogram support (`NativeHistogramBucketFactor` 1.1). |
| `link_rtt_seconds_bucket/sum/count` | Histogram | `source`, `target`, `address` | Classic-bucket series; quantiles, means, and jitter are derived in PromQL over any window. |
| `link_rto_seconds` | Gauge | `source`, `target`, `address` | Current adaptive RTO in use (RFC 6298, floored at 200ms). |
| `link_server_probes_received_total` | Counter | `source`, `client` | Valid probes received by the server, per remote client IP (server mode only). |

Derived values (percentiles, loss, jitter) are deliberately **not**
pre-computed in the exporter — Prometheus `rate()` / `histogram_quantile()`
compute them from the raw counters and histogram, so any time window
(1m, 1h, 24h) can be queried.

## PromQL Examples

### Link Packet Loss (%)

Loss is derived from the counters over any window:

```
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])
```

This is **application-visible** loss, not raw network loss. Each probe
is a single TCP segment, and the kernel retransmits lost segments (TCP
RTO ~1s, doubling). Segments recovered faster than the client's adaptive
RTO still count as received — with inflated RTT. With a link loss
simulator (e.g. clumsy) at X%, expect the loss ratio to sit notably
below X%, while RTT percentiles climb.

While the client cannot connect at all, no probes are sent, so the rate
ratio above becomes NaN (0/0). To show **100% during a full outage**
instead of a gap, OR the ratio with the down state:

```
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m]) OR (link_up == 0) * 100
```

`OR` takes the left side whenever it has a value, and falls back to 100%
only while the link is down. Pair it with `link_up == 0` and
`rate(link_connect_failures_total[5m]) > 0` for alerting on reachability.

To measure true network loss, run the server at the remote site and
compare its per-client `link_server_probes_received_total` against the
client's `link_probes_sent_total`. The server counter is labelled with
the remote client address (`client="203.0.113.5"`); select it explicitly
to correlate with the client's series:

```
100 * (1 - rate(link_server_probes_received_total{client="203.0.113.5"}[5m])
           / rate(link_probes_sent_total{target="site-b"}[5m]))
```

Segments never delivered to the server are genuinely lost on the wire —
no retransmission can hide them there.

### Average Latency (RTT)

```
rate(link_rtt_seconds_sum[5m]) / rate(link_rtt_seconds_count[5m])
```

### Median / 90th / 99th Percentile Latency

```
histogram_quantile(0.5,  rate(link_rtt_seconds_bucket[5m]))
histogram_quantile(0.9,  rate(link_rtt_seconds_bucket[5m]))
histogram_quantile(0.99, rate(link_rtt_seconds_bucket[5m]))
```

Explicit buckets cover sub-100ms LAN RTTs (5ms lower bound) up to 10s
of link degradation; values beyond 10s land in `+Inf`. The native
histogram (bucket factor 1.1) carries fine-grained data; Prometheus
scrapes and aggregates it transparently when native-histogram support
is enabled.

### Jitter (p90 − p50)

```
(histogram_quantile(0.9, rate(link_rtt_seconds_bucket[5m]))
 - histogram_quantile(0.5, rate(link_rtt_seconds_bucket[5m]))) * 1000
```

### Detecting a Baseline Shift (latency change detection)

Compare the current window against a longer baseline. Latency drift on a
long-running link shows up as the recent p50 diverging from a 24h
minimum:

```
histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m]))
  > min_over_time(histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m]))[24h]) * 1.5
```

Outages show up immediately in `link_up == 0`,
`rate(link_probes_timed_out_total[5m]) > 0`, and the adaptive RTO climbing
via `link_rto_seconds`.

### Connection Status

```
link_up
```

### Outage Alerts

```
alert: LinkDown
  expr: link_up == 0
  for:  1m

alert: LinkLossHigh
  expr: rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m]) > 0.2
  for:  5m

alert: LinkLatencyDegraded
  expr: histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m])) > min_over_time(histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m]))[24h]) * 1.5
  for:  10m
```

## Practical Monitoring Guide

Every query below works in both Prometheus and Grafana. "Now" = run it
as an **instant query** (Prometheus console, or a Grafana stat/single
stat panel). "Over time" = run the **same query** in a Grafana time
series panel — the same expression renders the history.

### Latency

**Latency now** (median RTT over the last 5 minutes; the smallest
window that produces a stable value):

```
histogram_quantile(0.5, rate(link_rtt_seconds_bucket[5m]))
```

**Latency over time** — same expression in a time series panel. Swap
`0.5` for `0.9` / `0.99` for the higher percentiles, or use the mean:

```
rate(link_rtt_seconds_sum[5m]) / rate(link_rtt_seconds_count[5m])
```

Note: when the link is fully down no RTT samples exist, so latency
panels show a gap (not 0) during the outage — combine with `link_up`
to see the down period.

### Packet Loss

**Loss now** (percentage over the last 5 minutes):

```
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])
```

**Loss over time** — same expression in a time series panel. Change
`[5m]` to `[1h]` / `[24h]` for longer windows.

**Show 100% during an outage** (instead of a gap, which the raw ratio
produces when no probes are sent):

```
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m]) OR (link_up == 0) * 100
```

For **true wire loss** (what a link-loss simulator injects — the client
ratio is masked by TCP retransmission), compare the server counter with
the client's sent counter:

```
100 * (1 - rate(link_server_probes_received_total{client="203.0.113.5"}[5m]) / rate(link_probes_sent_total{target="site-b"}[5m]))
```

### Recording Rules (cheap graphs at scale)

`rate()` recomputes on every query. For many links, precompute the
5-minute rates with recording rules so dashboards and alerts are cheap:

```yaml
groups:
  - name: link.rules
    rules:
      - record: link:rtt_p50_seconds:5m
        expr: histogram_quantile(0.5, rate(link_rtt_seconds_bucket[5m]))
      - record: link:loss_ratio:5m
        expr: rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])
      - record: link:loss_ratio:5m_withoutage
        expr: rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m]) OR (link_up == 0)
```

Graph `link:loss_ratio:5m_withoutage * 100` for the outage-inclusive
loss panel.

## Grafana Alloy Scraping

The example below scrapes the metrics endpoint, keeps only `link_*`
metrics (dropping `go_*`, `process_*`, and the Prometheus client's own
internals to save remote-write bandwidth and storage), and forwards the
result to a `prometheus.remote_write` component.

Add your own `prometheus.remote_write "default"` block (endpoint URL,
credentials) — it is intentionally not included here. If the remote
write component has a different name, update the
`prometheus.remote_write.default.receiver` reference below.

```river
prometheus.scrape "tcp_ping" {
	targets = [{
		"__address__" = "localhost:2112",
	}]
	metrics_path    = "/metrics"
	scrape_interval = "1m"
	scrape_timeout  = "10s"
	forward_to      = [prometheus.relabel.tcp_ping_keep.receiver]
}

prometheus.relabel "tcp_ping_keep" {
	rule {
		source_labels = ["__name__"]
		regex         = "link_.*"
		action        = "keep"
	}
	forward_to = [prometheus.remote_write.default.receiver]
}
```

If the agent and the prober run on different hosts, replace
`localhost:2112` with the prober's address. With metrics basic auth
enabled, add a `basic_auth` block to the scrape targets instead:

```river
prometheus.scrape "tcp_ping" {
	targets = [{
		"__address__" = "10.0.0.5:2112",
	}]
	...
	basic_auth {
		username = "monitoring"
		password = "secret"
	}
}
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
| `-source` | `""` | Source label applied to every metric series, e.g. the local site or datacenter (`sydney-dc`) |
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
