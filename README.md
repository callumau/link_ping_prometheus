# Link Monitor (UDP Ping Prometheus Exporter)

A high-performance **point-to-point link monitor** for Prometheus written
in Go. It measures latency (RTT), packet loss, and jitter by sending
active **UDP echo probes** across the link, with adaptive timeout
capabilities (RFC 6298). Run one agent per node; each target in the
client config is one monitored point-to-point link — the path between
this node and that target's node.

**Why UDP:** no retransmission, so a probe without an echo within the
timeout is genuinely lost on the wire — the loss ratio is **true network
loss**. TCP-based probing can never show this: the kernel retransmits
lost segments and hides them as inflated RTT. It answers "is this link
degrading?" — it is not a proxy for what TCP applications experience.

## Table of Contents

- [Typical Deployment](#typical-deployment)
- [Run with Docker](#run-with-docker)
- [Metrics](#metrics)
- [PromQL Examples](#promql-examples)
  - [Quick Reference](#quick-reference)
  - [Link Packet Loss](#link-packet-loss)
  - [Latency](#latency)
  - [Jitter](#jitter)
  - [Baseline Shift Detection](#baseline-shift-detection)
  - [Link Status](#link-status)
  - [Outage Alerts](#outage-alerts)
- [Grafana Alloy Scraping](#grafana-alloy-scraping)
- [Build](#build)
- [Test](#test)
- [Usage](#usage)
- [Service](#service)
- [Grafana Dashboard](#grafana-dashboard)
- [Code Structure](#code-structure)
- [Wire Protocol](#wire-protocol)
- [Security](#security)

## Typical Deployment

1. **Remote site (B):** run the echo server (open UDP port 4000 in the
   firewall — the protocol is UDP, not TCP). The server is **fail-closed**:
   it only answers probers on the `-allow` list and will not start without
   one, so an `-allow` entry for site A's IP is required:
   `./link_ping_prometheus -mode=server -listen=":4000" -allow=203.0.113.5 -metrics=":2112"`
2. **Local site (A):** run the client, targeting site B's address, and
   tag every metric with the local topology label:
   `./link_ping_prometheus -mode=client -target="203.0.113.10:4000" -source="sydney-dc" -metrics=":2112"`
3. Scrape both `/metrics` endpoints into Prometheus (or forward via
   [Grafana Alloy](#grafana-alloy-scraping)) and open the bundled
   dashboard.

Each configured target is one monitored link. The dashboard gives the
per-link picture: `link_up` status, true packet loss (rate-derived), RTT
percentiles (p50/p90/p99), jitter, and adaptive RTO.

## Run with Docker

Multi-arch container images (`linux/amd64`, `linux/arm64`) are published
to [GitHub Container Registry](https://github.com/callumau/link_ping_prometheus/pkgs/container/link_ping_prometheus)
on every release tag:

```sh
docker pull ghcr.io/callumau/link_ping_prometheus:latest
```

The image runs as an unprivileged user (UID 65532). Server mode listens
on UDP 4000; the metrics endpoint is served on TCP 2112.

Echo server at the remote site (fail-closed: `-allow` is required):

```sh
docker run -d --name link-ping-server --restart=always \
  -p 4000:4000/udp -p 2112:2112 \
  ghcr.io/callumau/link_ping_prometheus:latest \
  -mode=server -listen=":4000" -allow=203.0.113.5
```

Client probing site B from site A (metrics only, no probe port needed):

```sh
docker run -d --name link-ping-client --restart=always \
  -p 2112:2112 \
  ghcr.io/callumau/link_ping_prometheus:latest \
  -mode=client -target="203.0.113.10:4000" -source="sydney-dc"
```

All [flags](#usage) work the same as the bare binary; file-based flags
(`-targets` JSON, TLS cert/key) need those files mounted into the scratch
image, e.g. `-v /etc/link-ping:/cfg:ro -targets=/cfg/targets.json`.

## Metrics

The exporter exposes the following metrics at `/metrics` (default port 2112).

| Metric Name | Type | Labels | Description |
| --- | --- | --- | --- |
| `link_up` | Gauge | `source`, `target`, `address` | 1 while probes are getting echoes, 0 after 3 consecutive probes time out. A single lost probe or brief stall does not flap the state. |
| `link_probes_sent_total` | Counter | `source`, `target`, `address` | Total UDP probes sent. Probes into a down link still count as sent and time out naturally, so loss reads ~100% during an outage. |
| `link_probes_timed_out_total` | Counter | `source`, `target`, `address` | Total probes with no echo within the RTO — true network loss. |
| `link_probes_inflight` | Gauge | `source`, `target`, `address` | Current number of probes sent but waiting for a response or timeout. Grows during stalls. |
| `link_rtt_seconds` | Histogram | `source`, `target`, `address` | RTT histogram with explicit buckets `{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5}` s plus native histogram support (`NativeHistogramBucketFactor` 1.1). Buckets stop at 2.5s: anything slower than the RTO cap (3s) counts as loss, so higher buckets would never fill. |
| `link_rtt_seconds_bucket/sum/count` | Histogram | `source`, `target`, `address` | Classic-bucket series; quantiles and means are derived in PromQL over any window. |
| `link_rtt_jitter_seconds` | Gauge | `source`, `target`, `address` | Smoothed RTT jitter in seconds (RFC 3550 §6.4.1). Resets after a sequence gap (a timed-out probe), so link recovery never spikes the gauge. |
| `link_rto_seconds` | Gauge | `source`, `target`, `address` | Current adaptive RTO in use (RFC 6298, doubled on consecutive timeouts; floor `max(200ms, 2×SRTT)`). |
| `link_server_probes_received_total` | Counter | `source`, `client` | Valid probes received by the server, per remote client IP (server mode only). Cross-check against the client's sent counter. |
| `link_ping_build_info` | Gauge | `version` | Build version; value is always 1. Git tag for release builds, UTC timestamp to the minute for dev builds. |

Percentiles and loss are **not** pre-computed in the exporter — Prometheus
`rate()` / `histogram_quantile()` compute them from the raw counters and
histogram, so any time window (1m, 1h, 24h) can be queried. Jitter is the
one exception: it is a smoothed running estimate in the probe binary,
because a gauge derived from consecutive-sample deltas cannot be
reconstructed over arbitrary windows in PromQL.

## PromQL Examples

All queries run in both Prometheus and Grafana. Run them as **instant
queries** (Prometheus console, Grafana stat panel) for "now", or in a
**time series panel** for "over time" — the same expression renders both.
RTT metrics are **seconds**; multiply by `1000` for ms.

### Quick Reference

Copy-paste these.

| You want | Query | Unit |
| --- | --- | --- |
| **Packet loss** (incl. full outages) | `100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])` | % |
| **Latency** median (p50) | `histogram_quantile(0.5, rate(link_rtt_seconds_bucket[5m]))` | s → ×1000 = ms |
| **Latency** mean | `rate(link_rtt_seconds_sum[5m]) / rate(link_rtt_seconds_count[5m])` | s → ×1000 = ms |
| **Latency** p90 / p99 | `histogram_quantile(0.9, ...)` / `histogram_quantile(0.99, ...)` | s → ×1000 = ms |
| **Jitter** (instantaneous) | `link_rtt_jitter_seconds * 1000` | ms |
| **Jitter** (window-based) | `(histogram_quantile(0.9, rate(link_rtt_seconds_bucket[5m])) - histogram_quantile(0.5, rate(link_rtt_seconds_bucket[5m]))) * 1000` | ms |
| **Link up** | `link_up` | 0/1 |
| **Baseline shift** (recent p50 vs 24h min) | `histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m])) > min_over_time(histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m]))[24h]) * 1.5` | bool |
| **True wire loss** (needs server at remote end) | `100 * (1 - rate(link_server_probes_received_total{client="<ip>"}[5m]) / rate(link_probes_sent_total[5m]))` | % |

Two rules that trip people up:

- **Never divide raw counter totals.** Counters accumulate forever, so
  `timed_out / sent` on the raw /metrics dump is a *lifetime average*.
  Always wrap them in `rate()` (or `increase()`) over a window.
- **The rate window sets what you see.** It is both the smoothing period
  and the shortest outage that reads as a full 100% loss block. A `[5m]`
  window shows a 3-minute outage as a partial spike; `[1m]` catches it as
  100% but is noisier. Pick the window to match the outages you want to
  catch (the exporter's probe cadence does not limit visibility — every
  down second lands in the counters regardless of scrape interval).

### Link Packet Loss

```promql
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])
```

True network loss: each probe is a UDP datagram and UDP never
retransmits, so a probe without an echo within the RTO was genuinely lost
on the wire. With a link loss simulator (e.g. clumsy) at X%, expect the
ratio to read X%. During a full outage probes are sent into the void and
time out naturally, so the ratio reads **~100%** — no fabricated counters
and no PromQL `OR` workaround. Pair with `link_up == 0` for reachability
alerts.

**Sanity check:** `link_probes_sent_total` always equals
`link_rtt_seconds_count` (received) + `link_probes_timed_out_total` +
`link_probes_inflight`. If that sum ever differs, counters were lost or
the client socket stalled.

**Cross-check with the server** (server mode at the remote end):
`link_server_probes_received_total` counts valid probes per remote client
IP. Any mismatch with `link_probes_sent_total` is probes that never
reached the server — genuinely lost on the wire:

```promql
100 * (1 - rate(link_server_probes_received_total{client="203.0.113.5"}[5m])
           / rate(link_probes_sent_total{target="site-b"}[5m]))
```

**Why the loss ratio stays honest:** the adaptive RTO is RFC 6298
(`SRTT + 4×RTTVAR`, doubled on consecutive timeouts so it recovers when
latency jumps above the current value), floored at `max(200ms, 2×SRTT)`
rather than a fixed 200ms — a fixed floor counts normal jitter on links
whose RTT approaches it (e.g. ~185ms) as loss and pins the RTO at its 3s
clamp. Flooring at twice the smoothed RTT guarantees headroom and keeps
the loss ratio meaningful.

### Latency

```promql
rate(link_rtt_seconds_sum[5m]) / rate(link_rtt_seconds_count[5m])   # mean
histogram_quantile(0.5,  rate(link_rtt_seconds_bucket[5m]))         # p50
histogram_quantile(0.9,  rate(link_rtt_seconds_bucket[5m]))         # p90
histogram_quantile(0.99, rate(link_rtt_seconds_bucket[5m]))         # p99
```

Returns seconds; `* 1000` for ms. No RTT samples exist while the link is
fully down, so latency is a gap (not 0) during an outage — combine with
`link_up`.

Explicit buckets cover sub-100ms LAN RTTs (5ms lower bound) up to 2.5s
of degradation; values beyond 2.5s land in `+Inf`. Buckets stop at 2.5s
because the RTO cap (3s) bounds measurable RTT: probes slower than that
are counted as loss, not latency. The native histogram (bucket factor
1.1) carries fine-grained data; Prometheus scrapes and aggregates it
transparently when native-histogram support is enabled.

### Jitter

```promql
link_rtt_jitter_seconds * 1000
```

Smoothed RFC 3550 jitter computed in the probe binary from consecutive
RTT deltas — instantaneous value, no window needed. The estimate resets
after any timed-out probe, so recovery does not show an artificial spike.
For jitter over a specific time range, use the p90−p50 spread as a
window-based approximation:

```promql
(histogram_quantile(0.9, rate(link_rtt_seconds_bucket[5m]))
 - histogram_quantile(0.5, rate(link_rtt_seconds_bucket[5m]))) * 1000
```

### Baseline Shift Detection

```promql
histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m]))
  > min_over_time(histogram_quantile(0.5, rate(link_rtt_seconds_bucket[10m]))[24h]) * 1.5
```

Latency drift on a long-running link shows up as the recent p50 diverging
from a 24h minimum. Outages show up immediately in `link_up == 0`,
`rate(link_probes_timed_out_total[5m]) > 0`, and the adaptive RTO climbing
via `link_rto_seconds`.

### Link Status

```promql
link_up
```

### Outage Alerts

```yaml
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
prometheus.scrape "link_ping" {
 targets = [{
  "__address__" = "localhost:2112",
 }]
 metrics_path    = "/metrics"
 scrape_interval = "1m"
 scrape_timeout  = "10s"
 forward_to      = [prometheus.relabel.link_ping_keep.receiver]
}

prometheus.relabel "link_ping_keep" {
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
prometheus.scrape "link_ping" {
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
go build -o ./build/link_ping_prometheus .
```

Cross-compile for Windows:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o build/link_ping_prometheus.exe .
```

## Test

```sh
go test -count=1 ./test/...
```

Release binaries for Linux, macOS, Windows at [Latest Release](https://github.com/callumau/link_ping_prometheus/releases/latest).

## Usage

```sh
link_ping_prometheus -mode=<mode> [flags]
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-mode` | `server` | Operation mode: `server`, `client`, `both` |
| `-listen` | `:4000` | Server listen address |
| `-allow` | `""` | Server: comma-separated client IP allowlist (fail-closed — required in `server`/`both` mode) |
| `-target` | `""` | Client: single target `host:port` |
| `-targets` | `""` | Client: path to JSON targets file |
| `-metrics` | `:2112` | Prometheus metrics HTTP listen address |
| `-interval` | `500ms` | Client: probe interval |
| `-timeout` | `1s` | Client: Base/initial probe timeout |
| `-adaptive` | `true` | Enable adaptive RTO based on link quality |
| `-source` | `""` | Source label applied to every metric series, e.g. the local site or datacenter (`sydney-dc`) |
| `-metrics-user` | `""` | Basic auth username for /metrics (empty = disabled; env `LINK_PING_METRICS_USER`) |
| `-metrics-pass` | `""` | Basic auth password for /metrics (env `LINK_PING_METRICS_PASS`; prefer env over CLI to avoid `ps` exposure) |
| `-metrics-tls-cert` | `""` | TLS certificate file for /metrics (requires `-metrics-tls-key`) |
| `-metrics-tls-key` | `""` | TLS private key file for /metrics (requires `-metrics-tls-cert`) |
| `-json-logs` | `false` | Output logs in JSON format |
| `-log-file` | `""` | Append logs to this file in addition to stdout (required for Windows service logging, where stdout is discarded) |
| `-svc` | `""` | Windows service action: `install`, `uninstall`, `start`, `stop`, `run` |

Resource footprint: metric handles are resolved once per target at startup (no per-probe label lookups), and the Go heap is soft-capped at 128MB (`GOMEMLIMIT` env overrides) so RSS stays flat on long runs.

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
./link_ping_prometheus -mode=client -target="192.168.1.71:4000" -interval=10ms -timeout=20ms -metrics=":2113"
```

Client (multiple targets):

```sh
./link_ping_prometheus -mode=client -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113"
```

Server:

```sh
./link_ping_prometheus -mode=server -listen=":4000" -allow=192.168.1.71 -metrics=":2112"
```

Both:

```sh
./link_ping_prometheus -mode=both -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113"
```

## Service

### Windows

Use `-svc` to install/uninstall/start/stop/run. The tool records runtime flags at install time (excluding `-svc`, `-metrics-user`, and `-metrics-pass`). Metrics auth credentials are **not** persisted into the service configuration; set `LINK_PING_METRICS_USER` / `LINK_PING_METRICS_PASS` in the service environment instead (a warning is printed at install time).

```sh
link_ping_prometheus.exe -mode=both -targets=targets.json -interval=10ms -timeout=20ms -metrics=":2113" -svc=install
```

### Linux (systemd)

Create `/etc/systemd/system/link_ping_prometheus.service`:

```ini
[Unit]
Description=Link Ping Prometheus (UDP link monitor)
After=network.target

[Service]
ExecStart=/usr/local/bin/link_ping_prometheus -mode=server -listen=":4000" -allow=203.0.113.5 -metrics=":2112"
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

Note: In client/both mode, use an absolute path for `-targets` (e.g., `-targets=/etc/link_ping_prometheus/targets.json`).

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now link_ping_prometheus
```

## Grafana Dashboard

Prebuilt dashboard at [grafana-dashboard.json](grafana-dashboard.json).

[![Grafana dashboard screenshot](.docs/screenshot01.png)](.docs/screenshot01.png)

## Code Structure

```text
main.go                     — CLI wrapper, flag parsing, service lifecycle
main_test.go                — lifecycle race, auth/TLS flag validation tests
internal/prober/
  prober.go                 — Config, protocol constants
  adaptive.go               — RFC 6298 RTO estimation (AdaptiveStats)
  client.go                 — Target, LoadTargets, RunClient, UDP probe loop
  server.go                 — UDP echo responder, per-IP/global rate limits
  metrics.go                — Prometheus metric vars, InitMetrics, MetricsAuth
  validate.go               — Target address validation (ValidateTarget)
test/
  helpers_test.go           — Test utilities (metric inspectors, UDP echo server)
  adaptive_test.go          — AdaptiveStats logic and jitter adaptation
  validation_test.go        — LoadTargets, target parsing, Config validation
  server_test.go            — Server garbage handling, rate limits, shutdown
  client_test.go            — Robustness: loss, latency, corruption, spoofing, stalls, duplicates
  metrics_test.go           — Basic auth handler, metric seeding
  integration_test.go       — Multi-target, server dropout, stress (10 targets)
```

## Wire Protocol

UDP datagram, 24 bytes per probe:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Magic header `LNKPING\x00` |
| 8 | 8 | Sequence number (little-endian uint64) |
| 16 | 8 | Client timestamp (Unix ns, little-endian uint64) |

The server validates the magic header and exact 24-byte length before
echoing; anything else is dropped silently. The client additionally
requires the echoed timestamp to exactly match the value it sent —
corrupted, replayed, or spoofed responses are discarded and counted as
loss on timeout, protecting RTT samples from poisoning.

The server rate-limits echo processing to 1000 packets/s per remote IP
and 10000 packets/s globally (fixed one-second window); excess datagrams
are dropped. The probe loop keeps a single connected UDP socket per
target, but re-dials every 5 minutes (only when no probes are in flight)
so a target hostname that changes IP via DNS is re-resolved; a transient
DNS failure at startup is retried, not fatal.

## Security

- The UDP echo server validates the magic header and exact datagram size
  before echoing to prevent arbitrary payload reflection, and rate-limits
  echo processing per source IP and globally.
- Echoed timestamps are validated exactly (see Wire Protocol), so off-path
  corruption and replays cannot fabricate RTT samples.
- UDP is not amplification-prone (echo is the same size as the request)
  and carries no state, but any internet-facing echo endpoint should be
  firewall-restricted to known monitoring sites.
- The `/metrics` endpoint supports HTTP Basic Auth (`-metrics-user` / `-metrics-pass`) with constant-time comparison over hashed credentials. Both must be set together; the process refuses to start with only one.
- Prefer the `LINK_PING_METRICS_USER` / `LINK_PING_METRICS_PASS` environment variables over CLI flags — flag values are visible in `ps` to other local users.
- Basic Auth without TLS sends credentials as base64 on the wire; a startup warning is logged in that configuration. Use `-metrics-tls-cert` / `-metrics-tls-key` to serve `/metrics` over HTTPS.
- The wire protocol carries no sensitive data (sequence numbers and wall-clock timestamps only) and has no TLS — intended for internal network monitoring. Restrict access with a firewall on untrusted networks.
