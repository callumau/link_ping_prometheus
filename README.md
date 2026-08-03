# Link Monitor (UDP Ping Prometheus Exporter)

A high-performance **site-to-site link monitor** for Prometheus written
in Go. It measures latency (RTT), packet loss, and jitter by sending
active **UDP echo probes** across the link, with adaptive timeout
capabilities (RFC 6298).

The purpose is the status of the **link itself** between sites (or cores):
one agent per site, and each target in the client config is one monitored
link. Loss, latency, jitter, and up/down state together give the full
picture of link health. Because it probes the network path directly, it
answers "is this link degrading?" — it is not a proxy for what TCP
applications experience (TCP hides loss as delay; UDP shows it plainly).

UDP is used deliberately: there is no retransmission, so a probe without
an echo within the timeout is genuinely lost on the wire. The loss ratio
is **true network loss** — TCP-based probing can never show this, because
the kernel retransmits lost segments and hides them as inflated RTT.

## Typical Deployment: Site A ↔ Site B

1. **Remote site (B):** run the echo server (open UDP port 4000 in the
   firewall — the protocol is UDP, not TCP):
   `./tcp_ping_prometheus -mode=server -listen=":4000" -metrics=":2112"`
2. **Local site (A):** run the client, targeting site B's address, and
   tag every metric with the local topology label:
   `./tcp_ping_prometheus -mode=client -target="203.0.113.10:4000" -source="sydney-dc" -metrics=":2112"`
3. Scrape both `/metrics` endpoints into Prometheus (or forward via
   Grafana Alloy, see below) and open the bundled dashboard.

Each configured target is one monitored link. The dashboard gives the
per-link picture: `link_up` status, true packet loss (rate-derived), RTT
percentiles (p50/p90/p99), jitter, and adaptive RTO.

## Metrics

The exporter exposes the following metrics at `/metrics` (default port 2112).

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `link_up` | Gauge | `source`, `target`, `address` | 1 if an echo was received within the last RTO+interval, 0 otherwise. |
| `link_probes_sent_total` | Counter | `source`, `target`, `address` | Total UDP probes sent. Probes into a down link still count as sent and time out naturally, so loss reads ~100% during an outage. |
| `link_probes_timed_out_total` | Counter | `source`, `target`, `address` | Total probes with no echo within the RTO. True network loss — UDP never retransmits. |
| `link_probes_inflight` | Gauge | `source`, `target`, `address` | Current number of probes sent but waiting for a response or timeout. Grows during stalls. |
| `link_rtt_seconds` | Histogram | `source`, `target`, `address` | RTT histogram with explicit buckets `{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}` s plus native histogram support (`NativeHistogramBucketFactor` 1.1). |
| `link_rtt_seconds_bucket/sum/count` | Histogram | `source`, `target`, `address` | Classic-bucket series; quantiles, means, and jitter are derived in PromQL over any window. |
| `link_rto_seconds` | Gauge | `source`, `target`, `address` | Current adaptive RTO in use (RFC 6298, doubled on consecutive timeouts). Floor is `max(200ms, 2×SRTT)` so a link's timeout always has headroom over its measured RTT. |
| `link_server_probes_received_total` | Counter | `source`, `client` | Valid probes received by the server, per remote client IP (server mode only). Cross-check against the client's sent counter. |

Derived values (percentiles, loss, jitter) are deliberately **not**
pre-computed in the exporter — Prometheus `rate()` / `histogram_quantile()`
compute them from the raw counters and histogram, so any time window
(1m, 1h, 24h) can be queried.

## PromQL Examples

### Quick Reference

Copy-paste these. RTT metrics are **seconds**; multiply by `1000` for ms.

| You want | Query | Unit |
|---|---|---|
| **Packet loss** (incl. full outages) | `100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])` | % |
| **Latency** median (p50) | `histogram_quantile(0.5, rate(link_rtt_seconds_bucket[5m]))` | s → ×1000 = ms |
| **Latency** mean | `rate(link_rtt_seconds_sum[5m]) / rate(link_rtt_seconds_count[5m])` | s → ×1000 = ms |
| **Latency** p90 / p99 | `histogram_quantile(0.9, ...)` / `histogram_quantile(0.99, ...)` | s → ×1000 = ms |
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

### Link Packet Loss (%)

Loss is derived from the counters over any window:

```
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])
```

This is **true network loss**. Each probe is a UDP datagram, and UDP
never retransmits: a probe without an echo within the RTO was genuinely
lost on the wire. With a link loss simulator (e.g. clumsy) at X%, expect
the ratio to read X%. (Compare TCP-based probing, where the kernel
retransmits lost segments and hides the loss as inflated RTT — that is
why this tool uses UDP.)

While the link is fully down, probes are sent into the void and time out
naturally, so the ratio above reads **~100% during a full outage** — no
fabricated counters and no PromQL `OR` workaround needed. Pair the ratio
with `link_up == 0` for alerting on reachability.

**Sanity check for the counters:** `link_probes_sent_total` always equals
`link_rtt_seconds_count` (received) + `link_probes_timed_out_total` +
`link_probes_inflight`. If that sum ever differs, counters were lost or
the client socket stalled.

The adaptive RTO keeps the timeout honest on the link's actual RTT: it is
RFC 6298 (`SRTT + 4×RTTVAR`, doubled on consecutive timeouts so it can
recover when latency jumps above the current value), and its floor is
`max(200ms, 2×SRTT)` rather than a fixed 200ms. A fixed floor is too tight
on links whose RTT approaches it (e.g. ~185ms), causing normal jitter to
count as loss and the RTO to pin at its 3s clamp; flooring at twice the
smoothed RTT guarantees headroom and keeps the loss ratio meaningful.

The server-side `link_server_probes_received_total` (per remote client
IP) is a useful cross-check on the client's `link_probes_sent_total` —
any mismatch is probes that never reached the server:

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

Returns **seconds**. For ms: `... * 1000`. No RTT samples exist while the
link is fully down, so latency is a gap (not 0) during an outage.

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

### Link Status

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

All latency queries return **seconds** — append `* 1000` for ms (the
dashboard does this for you).

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

All loss queries return **percent**. Never divide raw counter totals —
always `rate()` over a window (see Quick Reference).

**Loss now** (percentage over the last 5 minutes):

```
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])
```

**Loss over time** — same expression in a time series panel. Change
`[5m]` to `[1h]` / `[24h]` for longer windows.

**Which window?** `[5m]` smooths and is the standard panel default. To
catch short outages as a full 100% block, shrink the window so it is not
much larger than the outage duration: a 1-minute outage reads ~100% with
`[1m]` but only bumps a `[5m]` panel. The counters never miss a down
second regardless of scrape interval.

**Show 100% during an outage** — no workaround needed. Probes sent into a
fully down link time out naturally, so the raw ratio reads ~100% instead
of a gap:

```
100 * rate(link_probes_timed_out_total[5m]) / rate(link_probes_sent_total[5m])
```

**Cross-check with the server:** the client ratio is already true loss
(UDP never retransmits). The server-side counter provides a second
opinion — probes that never reached the server:

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
```

The loss ratio already reads ~100% during outages (probes into a down
link time out naturally), so no separate outage-inclusive rule is
required. Graph `link:loss_ratio:5m * 100` for the loss panel.

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
| `-interval` | `500ms` | Client: probe interval |
| `-timeout` | `1s` | Client: Base/initial probe timeout |
| `-adaptive` | `true` | Enable adaptive RTO based on link quality |
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
Description=TCP Ping Prometheus (UDP link monitor)
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
|---|---|---|
| 0 | 8 | Magic header `TCPPING\x00` |
| 8 | 8 | Sequence number (little-endian uint64) |
| 16 | 8 | Client timestamp (Unix ns, little-endian uint64) |

The server validates the magic header and exact 24-byte length before
echoing; anything else is dropped silently. The client additionally
requires the echoed timestamp to exactly match the value it sent —
corrupted, replayed, or spoofed responses are discarded and counted as
loss on timeout, protecting RTT samples from poisoning.

The server rate-limits echo processing to 1000 packets/s per remote IP
and 10000 packets/s globally (fixed one-second window); excess datagrams
are dropped. There are no connections to manage: the probe loop is a
single reader, and `-interval` only needs to stay below the client's
`-timeout` (and, for loss accuracy, below the RTO).

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
- Prefer the `TCP_PING_METRICS_USER` / `TCP_PING_METRICS_PASS` environment variables over CLI flags — flag values are visible in `ps` to other local users.
- Basic Auth without TLS sends credentials as base64 on the wire; a startup warning is logged in that configuration. Use `-metrics-tls-cert` / `-metrics-tls-key` to serve `/metrics` over HTTPS.
- The wire protocol carries no sensitive data (sequence numbers and wall-clock timestamps only) and has no TLS — intended for internal network monitoring. Restrict access with a firewall on untrusted networks.
