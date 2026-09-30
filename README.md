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
- [Alert Rules File](#alert-rules-file)
- [Deployment (Ansible)](#deployment-ansible)
- [Grafana Alloy Scraping](#grafana-alloy-scraping)
- [Build](#build)
- [Test](#test)
- [Usage](#usage)
  - [Flags](#flags)
  - [Memory & Runtime Tuning](#memory--runtime-tuning)
  - [Targets File](#targets-file)
  - [Examples](#examples)
- [Installation](#installation)
  - [Service](#service)
    - [Windows](#windows)
    - [Linux (systemd)](#linux-systemd)
- [Grafana Dashboard](#grafana-dashboard)
- [Code Structure](#code-structure)
- [Wire Protocol](#wire-protocol)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

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
  -mode=server -listen=":4000" -allow=203.0.113.5 -metrics=":2112"
```

Client probing site B from site A (metrics only, no probe port needed):

```sh
docker run -d --name link-ping-client --restart=always \
  -p 2112:2112 \
  ghcr.io/callumau/link_ping_prometheus:latest \
  -mode=client -target="203.0.113.10:4000" -source="sydney-dc" -metrics=":2112"
```

`-metrics=":2112"` is required in both examples: the binary's default
bind is `127.0.0.1:2112`, which is unreachable through the container's
published `-p 2112:2112` port.

All [flags](#usage) work the same as the bare binary; file-based flags
(`-targets` JSON, TLS cert/key) need those files mounted into the scratch
image, e.g. `-v /etc/link-ping:/cfg:ro -targets=/cfg/targets.json`.

## Metrics

The exporter exposes the following metrics at `/metrics` (default port 2112).

| Metric Name | Type | Labels | Description |
| --- | --- | --- | --- |
| `link_up` | Gauge | `source`, `target`, `address` | 1 while probes are getting echoes, 0 after 3 consecutive probes time out or probing becomes structurally impossible (persistent local send failures, dial/DNS retry). A single lost probe or brief stall does not flap the state. |
| `link_probes_sent_total` | Counter | `source`, `target`, `address` | Total UDP probes sent. Probes into a down link still count as sent and time out naturally, so loss reads ~100% during an outage. |
| `link_probes_timed_out_total` | Counter | `source`, `target`, `address` | Total probes whose echo did not arrive within their RTO — true network loss. A probe is retired at the first probe tick *after* its deadline, so with `-interval` ≤ `-timeout` an echo up to one interval late still counts as latency, never loss (the effective deadline is RTO + up to one interval). |
| `link_probes_corrupted_total` | Counter | `source`, `target`, `address` | Probes whose echo came back with corrupted payload bytes (`-payload` mode only): magic, sequence and timestamp intact, data altered in flight. Data-path corruption, not loss — the round trip completed. |
| `link_mtu_probes_sent_total` | Counter | `source`, `target`, `address` | DF-set probes sent by the periodic MTU sweep (`-mtu-sweep`), counted per ATTEMPT: a size that gets no echo is retried once before the search steps down, so this is a probe rate, not a distinct-size rate (up to ~2x the probes for the same path; a healthy full-size path still costs one). Deliberately separate from the main counters: never in the loss ratio or the sent/rtt/timed_out balance. |
| `link_mtu_probes_lost_total` | Counter | `source`, `target`, `address` | DF-set MTU probes with no echo, per attempt like `sent` (a size that fails twice counts twice), so lost/sent stays a per-probe ratio: sizes the path does not survive. Rising lost with healthy main probes = PMTUD blackhole (works-small-fails-big). Alert on the ratio (e.g. `> 0.2`), not on `> 0` — one retried probe on a 1%-loss path moves it. |
| `link_path_mtu_bytes` | Gauge | `source`, `target`, `address` | Largest probe frame (header + payload, excluding IP/UDP overhead) that round-trips with DF set; 0 until the first successful sweep. A full-size Ethernet path reads 1424, or 1432 with `-echo-secret` (the header grows from 24 to 32 bytes there). |
| `link_probes_send_errors_total` | Counter | `source`, `target`, `address` | Probes that failed to send locally (UDP write errors). Never on the wire, so never in `link_probes_sent_total`; sustained rate means a local NIC/socket problem, not network loss. |
| `link_prober_internal_errors_total` | Counter | `source`, `target`, `address`, `reason` | Prober-internal failures (`reason`: `panic`, `reader_dead`, `dial_retry`, `stop_timeout`) — not link conditions. A rising rate means this target's probe numbers are unreliable; check the agent's own logs and socket state. |
| `link_probes_inflight` | Gauge | `source`, `target`, `address` | Current number of probes sent but waiting for a response or timeout. Grows during stalls. |
| `link_rtt_seconds` | Histogram | `source`, `target`, `address` | RTT histogram with explicit buckets `{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 3.0}` s plus native histogram support (`NativeHistogramBucketFactor` 1.1). Buckets stop at 3s, the RTO cap: an echo that misses its RTO is normally counted as loss and discarded, so higher edges stay empty — except for the samples above 3s that can still occur: a link whose SRTT exceeds 1.5s applies a timeout above the cap (floor `2×SRTT`), a fixed `-timeout` above 3s does the same, and an echo that misses its RTO by up to one probe interval is still recorded (see the timeout row above). |
| `link_rtt_seconds_bucket/sum/count` | Histogram | `source`, `target`, `address` | Classic-bucket series; quantiles and means are derived in PromQL over any window. |
| `link_rtt_jitter_seconds` | Gauge | `source`, `target`, `address` | Smoothed RTT jitter in seconds (RFC 3550 §6.4.1). Resets to 0 on the first echo after a sequence gap (a timed-out probe), so link recovery never spikes the gauge; during a total outage it holds its last value until that echo. |
| `link_rto_seconds` | Gauge | `source`, `target`, `address` | Current adaptive RTO in use (RFC 6298, doubled on consecutive timeouts; floor `max(200ms, 2×SRTT)`). The 3s cap bounds the backoff value, **not** the floor: a link whose SRTT exceeds 1.5s applies a timeout above 3s, deliberately, or it would be read as loss. |
| `link_rtt_srtt_seconds` | Gauge | `source`, `target`, `address` | Smoothed RTT estimate (RFC 6298 SRTT), a window-independent latency signal for dashboards and baseline-shift alerts. Stays 0 with adaptive mode disabled. |
| `link_server_probes_received_total` | Counter | `source`, `client` | Valid probes received by the server, per remote client IP (server mode only). Cross-check against the client's sent counter — mismatches may also be echo write failures, see `link_server_echo_errors_total`. Includes MTU-sweep probes (they carry the same header frame), so subtract `rate(link_mtu_probes_sent_total)` before reading a mismatch as wire loss. A CIDR-matched client idle past the server's TTL loses this series and restarts it at 0 on return — see Security. |
| `link_server_echo_errors_total` | Counter | `source` | Validated probes the server failed to echo back (local UDP write error). The client counts these as loss, so subtract this rate before attributing a received/sent mismatch to the network. |
| `link_server_probes_dropped_total` | Counter | `source`, `reason` | Probes dropped by server: `allowlist`, `rate_ip`, `rate_global`, `size`, `magic`, `hmac`, `replay`, `invalid_addr`, `client_overflow`. `hmac`/`replay` diagnose secret/NTP misconfig vs true loss; `client_overflow` means more distinct CIDR-allowlisted client IPs than the per-client series cap; that cap is not the only way a per-client series ends — CIDR-matched clients idle past the server's TTL have their series deleted and restart at 0 if they return (see Security). |
| `link_server_clock_skew_seconds` | Gauge | `source`, `client` | Last observed clock skew (server minus client timestamp) for HMAC probes; positive means client behind. Diagnose replay drops from NTP drift per peer. |
| `link_metrics_auth_failures_total` | Counter | (none) | Rejected HTTP Basic auth attempts on `/metrics` and `/status`. A rising rate means a misconfigured scraper or credential scanning. |
| `link_ping_build_info` | Gauge | `version` | Build version; value is always 1. Git tag for release builds, UTC timestamp to the minute for dev builds. |

Percentiles and loss are **not** pre-computed in the exporter — Prometheus
`rate()` / `histogram_quantile()` compute them from the raw counters and
histogram, so any time window (1m, 1h, 24h) can be queried. Jitter is the
one exception: it is a smoothed running estimate in the probe binary,
because a gauge derived from consecutive-sample deltas cannot be
reconstructed over arbitrary windows in PromQL. The Prometheus client's own
`promhttp_metric_handler_requests_*` counters (scrapes by HTTP status) are
exported alongside the `link_*` series.

## PromQL Examples

All queries run in both Prometheus and Grafana. Run them as **instant
queries** (Prometheus console, Grafana stat panel) for "now", or in a
**time series panel** for "over time" — the same expression renders both.
RTT metrics are **seconds**; multiply by `1000` for ms.

### Quick Reference

Copy-paste these.

| You want | Query | Unit |
| --- | --- | --- |
| **Packet loss** (incl. full outages) | `clamp_max(100 * rate(link_probes_timed_out_total[$__rate_interval]) / rate(link_probes_sent_total[$__rate_interval]), 100)` | % (clamped at 100) |
| **Latency** median (p50) | `histogram_quantile(0.5, rate(link_rtt_seconds_bucket[$__rate_interval]))` | s → ×1000 = ms |
| **Latency** mean | `rate(link_rtt_seconds_sum[$__rate_interval]) / rate(link_rtt_seconds_count[$__rate_interval])` | s → ×1000 = ms |
| **Latency** p90 / p99 | `histogram_quantile(0.9, ...)` / `histogram_quantile(0.99, ...)` | s → ×1000 = ms |
| **Jitter** (instantaneous) | `link_rtt_jitter_seconds * 1000` | ms |
| **Jitter** (window-based) | `(histogram_quantile(0.9, rate(link_rtt_seconds_bucket[$__rate_interval])) - histogram_quantile(0.5, rate(link_rtt_seconds_bucket[$__rate_interval]))) * 1000` | ms |
| **Link up** | `link_up` | 0/1 |
| **Baseline shift** (recent p50 vs 24h min) | `link:rtt_seconds_p50 > 1.5 * link:rtt_seconds_p50_24h_min` (shipped recording rules) | bool |
| **True wire loss** (needs server at remote end) | `100 * (1 - (rate(link_server_probes_received_total{client="<ip>"}[$__rate_interval]) - rate(link_mtu_probes_sent_total[$__rate_interval])) / rate(link_probes_sent_total[$__rate_interval]))` | % |

Two rules that trip people up:

- **Never divide raw counter totals.** Counters accumulate forever, so
  `timed_out / sent` on the raw /metrics dump is a *lifetime average*.
  Always wrap them in `rate()` (or `increase()`) over a window.
- **The rate window sets what you see.** It is both the smoothing period
  and the shortest outage that reads as a full 100% loss block. A `[$__rate_interval]`
  window shows a 3-minute outage as a partial spike; `[1m]` catches it as
  100% but is noisier. Pick the window to match the outages you want to
  catch (the exporter's probe cadence does not limit visibility — every
  down second lands in the counters regardless of scrape interval).

### Link Packet Loss

```promql
100 * rate(link_probes_timed_out_total[$__rate_interval]) / rate(link_probes_sent_total[$__rate_interval])
```

True network loss: each probe is a UDP datagram and UDP never
retransmits, so a probe without an echo was genuinely lost on the wire.
The deadline is the RTO, applied at the first probe tick after it expires
(so with `-interval` ≤ `-timeout` a very late echo can still be recorded as
latency instead of loss; see the `link_probes_timed_out_total` row above).
With a link loss simulator (e.g. clumsy) at X%, expect the
ratio to read X%. During a full outage probes are sent into the void and
time out naturally, so the ratio reads **~100%** — no fabricated counters
and no PromQL `OR` workaround. Pair with `link_up == 0` for reachability
alerts.

**Sanity check:** `link_probes_sent_total` always equals
`link_rtt_seconds_count` (received) + `link_probes_timed_out_total` +
`link_probes_inflight` (plus `link_probes_corrupted_total` when `-payload`
is enabled). If that sum ever differs, counters were lost or the client
socket stalled.

**Cross-check with the server** (server mode at the remote end):
`link_server_probes_received_total` counts valid probes per remote client
IP. Any mismatch with `link_probes_sent_total` is probes that never
reached the server — genuinely lost on the wire. Two corrections apply
before that mismatch can be called network loss. `link_server_echo_errors_total`:
a validated probe the server failed to write back did reach the server but
never returned, so the client counts it as loss — subtract that rate.
`link_mtu_probes_sent_total`: the DF MTU sweep sends the same header frame
to the same address, so the server counts those probes too and on a default
`-mtu-sweep=1m` deployment `received` can exceed `sent`. Subtract the sweep
before reading a mismatch as loss:

```promql
# Labels differ between the two families (the server side carries
# {source,client}, the client side {source,target,address}), so a bare
# subtraction matches nothing; aggregate both sides instead. Narrow both
# client-side selectors to the target being cross-checked (and to one server
# client) — leaving the MTU term unfiltered over-subtracts on a client that
# probes more than one target.
100 * (1 - (sum(rate(link_server_probes_received_total{client="203.0.113.5"}[$__rate_interval]))
            - sum(rate(link_mtu_probes_sent_total{target="site-b"}[$__rate_interval])))
           / sum(rate(link_probes_sent_total{target="site-b"}[$__rate_interval])))
```

Sweep probes are visible to the server and must be subtracted here before
calling anything network loss — they are a separate counter namespace on the
client, not in `link_probes_sent_total`.

**Why the loss ratio stays honest:** the adaptive RTO is RFC 6298
(`SRTT + 4×RTTVAR`, doubled on consecutive timeouts so it recovers when
latency jumps above the current value), floored at `max(200ms, 2×SRTT)`
rather than a fixed 200ms — a fixed floor counts normal jitter on links
whose RTT approaches it (e.g. ~185ms) as loss and pins the RTO at its 3s
clamp. Flooring at twice the smoothed RTT guarantees headroom and keeps
the loss ratio meaningful.

One deliberate exception: when probes are in flight across the periodic
5-minute DNS re-dial (only possible with aggressive `-interval` values below
the RTO), those probes are force-timed-out and count as a small synthetic
loss each re-dial. On links whose RTT approaches or exceeds the probe
interval this produces a small phantom loss floor — roughly `RTO/interval`
probes per re-dial, i.e. ~0.3% loss on a 700ms-RTT link at the default
500ms interval. If your loss-ratio alert threshold sits near that floor,
raise `-reconnect-interval` (e.g. `24h`) so the re-dial happens at most
daily; DNS changes are then picked up at the next re-dial rather than
within 5 minutes.

### Latency

```promql
rate(link_rtt_seconds_sum[$__rate_interval]) / rate(link_rtt_seconds_count[$__rate_interval])   # mean
histogram_quantile(0.5,  rate(link_rtt_seconds_bucket[$__rate_interval]))         # p50
histogram_quantile(0.9,  rate(link_rtt_seconds_bucket[$__rate_interval]))         # p90
histogram_quantile(0.99, rate(link_rtt_seconds_bucket[$__rate_interval]))         # p99
```

Returns seconds; `* 1000` for ms. No RTT samples exist while the link is
fully down, so latency is a gap (not 0) during an outage — combine with
`link_up`.

Explicit buckets cover sub-100ms LAN RTTs (5ms lower bound) up to the
adaptive RTO cap at 3s; values beyond 3s land in `+Inf`. On a normal link
they are rare — an echo that outlives its own RTO by up to one probe
interval (the deadline is the first tick after it expires) is the regular
way to land there, and two configurations make it routine: a link whose
SRTT exceeds 1.5s (its applied timeout floors at 2×SRTT, above the 3s cap,
on purpose) and a fixed `-timeout` above 3s. The native
histogram (bucket factor 1.1) carries fine-grained data; Prometheus
scrapes and aggregates it transparently when native-histogram support is
enabled.

RTT samples are conservative by construction: a probe is timed when the
reader goroutine drains the echo, so reader-side buffering can only
inflate a sample, never deflate it. The echo server is also
single-threaded, so at very high aggregate probe rates the measured RTT
includes server queueing — keep the total probe rate well under the
documented per-IP and global rate caps.

### Jitter

```promql
link_rtt_jitter_seconds * 1000
```

Smoothed RFC 3550 jitter computed in the probe binary from consecutive
RTT deltas — instantaneous value, no window needed. The estimate resets
to 0 on the first echo after a sequence gap, so recovery does not show an
artificial spike; during a full outage the gauge holds its last value
until that echo arrives.
For jitter over a specific time range, use the p90−p50 spread as a
window-based approximation:

```promql
(histogram_quantile(0.9, rate(link_rtt_seconds_bucket[$__rate_interval]))
 - histogram_quantile(0.5, rate(link_rtt_seconds_bucket[$__rate_interval]))) * 1000
```

### Baseline Shift Detection

```promql
link:rtt_seconds_p50 > 1.5 * link:rtt_seconds_p50_24h_min
```

The shipped recording rules define both sides: `link:rtt_seconds_p50` (5m
median) and `link:rtt_seconds_p50_24h_min` (its 24h floor). Written out
directly, the baseline needs a subquery — `min_over_time((expr)[24h:5m])` —
because PromQL range selectors do not apply to function calls.

Latency drift on a long-running link shows up as the recent p50 diverging
from a 24h minimum. Outages show up immediately in `link_up == 0`,
`rate(link_probes_timed_out_total[$__rate_interval]) > 0`, and the adaptive RTO climbing
via `link_rto_seconds`.

### Link Status

```promql
link_up
```

### Outage Alerts

All outage alerts use a `for:` of at least 5m (loss and latency
warnings 10m) so brief events — host reboots, single probe blips, a 60s
maintenance restart — ride through without paging.
Anything that survives that window of continuous failure is a real outage.
Sub-scrape outages are still captured by the counters: a 30s blip between
scrapes never touches `link_up`, but it does land in
`rate(timed_out)/rate(sent)`, so the loss alert is the primary detector
and `link_up` is the state view for long outages.

```yaml
alert: HighPacketLoss
  expr: 100 * rate(link_probes_timed_out_total[$__rate_interval]) / rate(link_probes_sent_total[$__rate_interval]) > 5
  for:  10m

alert: SeverePacketLoss
  expr: 100 * rate(link_probes_timed_out_total[$__rate_interval]) / rate(link_probes_sent_total[$__rate_interval]) > 20
  for:  5m

alert: LinkDown
  expr: link_up == 0
  for:  5m

alert: LinkMonitorAbsent
  expr: absent(link_up)
  for:  10m

alert: LinkScrapeTargetDown
  expr: up{job="link_ping"} == 0
  for:  3m

alert: LinkMonitorSourceAbsent   # one rule per source, see below
  expr: absent_over_time(link_up{source="<site>"}[10m])

alert: LinkProbesStalled
  expr: rate(link_probes_sent_total[$__rate_interval]) == 0
  for:  5m

alert: LinkLatencyDegraded
  expr: link:rtt_seconds_p50 > 1.5 * link:rtt_seconds_p50_24h_min
  for:  10m
```

**`LinkProbesStalled` is required alongside the loss alert.** If the local
interface or route dies, probe writes fail and neither `sent` nor
`timed_out` moves — the loss ratio reads 0/0 (no data), not 100%. Only
`link_up == 0` (after 3 consecutive local send failures) and a flat
`rate(link_probes_sent_total)` reveal it; without this alert a dead local
link can look like a quiet, healthy monitor.

**Loss threshold:** 20% over the rate window means roughly 1 in 5 probes
lost for 5 continuous minutes — a heavily degraded but routing link.
Tune down (10%) for links where any sustained loss matters; a full outage
reads ~100% and is caught immediately by `SeverePacketLoss` regardless of
threshold, since the condition persists through the `for` duration.

## Alert Rules File

The alerts above ship ready-to-load in `rules/link-monitor.yml`: recording
rules (`link:loss_ratio`, `link:rtt_seconds_p50/p90/p99`,
`link:mean_rtt_seconds`, `link:rtt_seconds_p50_24h_min` — all with matching
`rate()` windows) and alerting
rules (`LinkDown`, `LinkMonitorAbsent`, `LinkScrapeTargetDown`,
`LinkMonitorSourceAbsent` (per-source template), `HighPacketLoss` 5%/10m,
`SeverePacketLoss` 20%/5m, `LinkProbesStalled`, `LinkProbeStall`,
`ProbeCorruption`, `ClientSendErrors`, `ProberInternalErrors`,
`MetricsAuthFailures`, `ServerDropsObserved`, `ServerEchoErrors`,
`LinkClockSkewHigh` (>20s skew), `LinkClockSkewCritical` (>25s skew,
replacing the former `ClockSkewApproaching`), `ServerReplayDrops` (replay
drops while `link_up` is still 1), `LinkLatencyDegraded`, `PathMtuDropped`,
`MtuProbeLossHigh` (lost/sent ratio > 0.2), `MtuSweepUnresolved`). Wire
them into Prometheus so alerting works out of the box instead of every
operator copying expressions from these docs:

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/link-monitor.yml
```

Validate before shipping: `promtool check rules rules/link-monitor.yml`.
Alert thresholds (5% warning for 10m, 20% critical for 5m) are starting
points — tune per link as with the expressions above.

The shipped set also covers the failure modes the loss ratio cannot:
`LinkProbesStalled` (nothing being sent), `LinkProbeStall` (probes stuck in
flight), and `LinkMonitorAbsent` (`absent(link_up)` — the agent or scrape
target is gone entirely, so missing data can never fire the other alerts).
`ProberInternalErrors`, `ServerEchoErrors`, `ProbeCorruption`, and
`MetricsAuthFailures` flag prober-local failures: while
`link_prober_internal_errors_total` or `link_server_echo_errors_total` is
rising, the affected target's numbers are unreliable — fix the cause
before trusting its loss ratio.

### Dead-Source Coverage

`LinkMonitorAbsent` is a global catch-all: `absent(link_up)` fires only
when *every* `link_up` series is gone. In a fleet with more than one
source, one dead prober leaves the others exporting, the expression stays
non-empty, and **nothing fires** — every `link_up`-keyed alert silently
resolves ~2 scrapes after the dead source stops exporting (Prometheus
marks the vanished series stale). Three shipped mechanisms close that gap:

1. **`LinkScrapeTargetDown`** (direct scraping): `up{job="link_ping"} == 0`
   for 3m fires ~3 scrapes after the exporter dies — the fastest signal,
   and it carries `job`/`instance` labels. The job name must match your
   scrape config (the README examples use `link_ping`); a wrong name makes
   the rule inert, so verify it once with an instant query. Not available
   for remote-write (Alloy) setups — the receiving Prometheus has no `up`
   for them.
2. **`LinkMonitorSourceAbsent`** (template in `rules/link-monitor.yml`, one
   rule per monitored source): `absent_over_time(link_up{source="site-a"}[10m])`.
   Why one rule per source is mandatory — and the blocks to copy — is
   worked through below.
3. **`LinkMonitorAbsent`** stays as the global fallback for
   single-source deployments and Prometheus-config-wide breakage. Do not
   load the file for scrape jobs that run `-mode=server` — `link_up` does
   not exist there and the alert would fire forever.

The handoff: a live-but-degraded link fires `LinkDown`/loss alerts while
data still flows; a dead source fires `LinkScrapeTargetDown`
(direct-scrape, fast) and/or `LinkMonitorSourceAbsent` (any transport,
~10–12m); the whole export path dying fires `LinkMonitorAbsent`. No state
leaves a silent gap.

#### Why one rule cannot see one dead source

Alert expressions evaluate per label set. When a prober stops exporting,
its `link_up` series stops being scraped; after ~2 scrape intervals
Prometheus marks it stale and it vanishes from instant evaluation. From
that moment every `link_up`-keyed expression returns an *empty vector*
for that source's labels — so alerts that were firing **resolve
silently**, and the rate/threshold alerts cannot even see 0 anymore.
`LinkMonitorAbsent` cannot help in a fleet: `absent(link_up)` returns a
result only when the selector matches **zero series globally**.

Worked example — sources `sydney-dc` and `london-dc`, 1m scrape interval,
sydney's prober process dies at T:

| time | what happens |
| ------ | -------------- |
| T | sydney's prober stops exporting `link_up` |
| ~T+2m | sydney's series goes stale and vanishes. `LinkDown` (if it was firing) auto-resolves; loss/stalled alerts for sydney see empty vectors, not 0 |
| any time | `LinkMonitorAbsent` stays quiet: london still exports, so the selector is never globally empty |
| ~T+11–12m | `absent_over_time(link_up{source="sydney-dc"}[10m])` — evaluated by the sydney rule — returns one synthetic series `{source="sydney-dc"}` and the alert fires |

Without the per-source rule the outcome is row 3 forever: **no alert at
all** for a completely dead prober. The [10m] window already encodes the
duration — adding a `for:` on top would only delay the fire to 15m.

#### Recommended alert setup

At deployment time, duplicate the `LinkMonitorSourceAbsent` template from
`rules/link-monitor.yml` once per source (the shipped file carries no
real source names; generate these from your targets inventory):

```yaml
- alert: LinkMonitorSourceAbsent
  expr: absent_over_time(link_up{source="sydney-dc"}[10m])
  labels:
    severity: critical
  annotations:
    summary: >-
      Source {{ $labels.source }} stopped exporting link_up

- alert: LinkMonitorSourceAbsent
  expr: absent_over_time(link_up{source="london-dc"}[10m])
  labels:
    severity: critical
  annotations:
    summary: >-
      Source {{ $labels.source }} stopped exporting link_up
```

- The **equality matcher** is load-bearing: `absent_over_time` copies
  equality matchers' labels onto the synthetic series, which is what
  makes `{{ $labels.source }}` resolve to the dead source in the
  notification. A regex matcher (`source=~"sydney-.*"`) produces an
  unlabeled `{}` series — and still only fires when *all* matching
  sources are gone, so one dead source among several passes silently.
- A source without its own rule has **no** dead-source coverage in
  remote-write deployments — adding a target means adding its rule.
- Direct-scrape deployments additionally get `LinkScrapeTargetDown`
  (~T+3–5m, faster, with `job`/`instance` labels); remote-write
  deployments rely on these per-source rules alone.
- Validate the file after generating:
  `promtool check rules rules/link-monitor.yml` (CI runs it too).

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
go test -count=1 ./...          # full suite (~2 min; CI also runs it under -race)
go vet ./...
SOAK_SECONDS=600 go test -count=1 -timeout 15m -run TestSoakMemory -v ./test/   # opt-in memory soak (heap must stay flat, +8MB ceiling; -timeout required, the default 10m expires mid-soak)
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
| `-allow` | `""` | Server: comma-separated client IP allowlist — plain IPs or CIDR prefixes like `203.0.113.0/24` (fail-closed — required in `server`/`both` mode) |
| `-target` | `""` | Client: single target `host:port` |
| `-targets` | `""` | Client: path to JSON targets file |
| `-metrics` | `127.0.0.1:2112` | Prometheus metrics HTTP listen address (localhost-only by default; use `:2112` to expose for remote scrape — firewall-restrict) |
| `-interval` | `500ms` | Client: probe interval (warns if `>= -timeout`; probes will queue). Values below `1ms` are rejected: the pending window grows as `RTO/interval`, so sub-millisecond intervals allocate without bound. The ratio is capped too — an effective `-timeout` more than 1000× the interval (e.g. `1ms`/`1m`) is rejected rather than accepted and swept every tick. |
| `-timeout` | `1s` | Client: Base/initial probe timeout (with `-adaptive=false` warns if `<200ms`; spurious loss on moderate-RTT links). An effective timeout more than 1000× `-interval` (global or per-target) is rejected: that ratio is the in-flight window size. |
| `-reconnect-interval` | `5m` | Client: How long to keep a UDP socket before re-dialing for DNS re-resolution (a non-zero value below `-interval` is rejected as an error; `0` falls back to the built-in 5m and only warns if that is below `-interval`; set e.g. `24h` to effectively disable) |
| `-dscp` | `0` | Client: DSCP value 0-63 marked on probe packets (e.g. 46 = EF) so QoS-managed networks class them accordingly. 0 = unmarked (default). Best effort, requires OS support (Linux). |
| `-payload` | `0` | Client: probe payload bytes beyond the 24/32-byte header (up to 1400), filled with a deterministic pattern and validated byte-for-byte on echo. Corruption counts in `link_probes_corrupted_total` — distinct from loss. Detects MTU/data-path corruption a small probe cannot see. |
| `-targets-reload-interval` | `0` | Client: poll the `-targets` file at this interval and apply changes without a restart (0 disables; SIGHUP also reloads on Unix; Windows services need this flag to reload) |
| `-mtu-sweep` | `1m` | Client: periodically sweep DF-set probe sizes to find the largest frame the path carries (`link_path_mtu_bytes`, `/status path_mtu_bytes`). 0 disables. Linux, and Windows for IPv4 targets on any Windows Server (2003+ via the DF flag; Server 2019+/Win10 1703+ use full path-MTU discovery); IPv6 targets need Server 2019+/Win10 1703+. Unsupported socket options disable just the sweep with a one-time warning. Separate counters — never in the loss ratio. |
| `-adaptive` | `true` | Enable adaptive RTO based on link quality. With `false`, the fixed `-timeout` applies: links whose true RTT exceeds it read as 100% loss with no warning — pick a timeout comfortably above expected RTT |
| `-source` | `""` | Source label applied to every metric series, e.g. the local site or datacenter (`sydney-dc`) (defaults to hostname) |
| `-metrics-user` | `""` | Basic auth username for /metrics (empty = disabled; env `LINK_PING_METRICS_USER`) |
| `-metrics-pass` | `""` | Basic auth password for /metrics (env `LINK_PING_METRICS_PASS`; prefer env over CLI to avoid `ps` exposure) |
| `-metrics-tls-cert` | `""` | TLS certificate file for /metrics (requires `-metrics-tls-key`) |
| `-metrics-tls-key` | `""` | TLS private key file for /metrics (requires `-metrics-tls-cert`) |
| `-metrics-allow-insecure` | `false` | Allow Basic Auth without TLS (otherwise auth over plaintext HTTP is rejected) |
| `-metrics-gzip` | `false` | Gzip-compress `/metrics` responses when the scraper offers it. Off by default because promhttp pools a gzip writer per CPU and each holds ~0.7MB of flate state, so compression costs up to ~0.7MB x `GOMAXPROCS` of live heap — more than a small fleet's whole response. Enable it for many targets. |
| `-mem-scavenge` | `5m` | Runtime: force a heap scavenge at this interval so the unused heap high-water mark is returned to the OS (0 disables; skipped unless at least 4MB of releasable heap is held, see [Memory & Runtime Tuning](#memory--runtime-tuning)). |
| `-json-logs` | `false` | Output logs in JSON format |
| `-log-file` | `""` | Append logs to this file in addition to stdout (required for Windows service logging, where stdout is discarded). The agent enforces mode `0600` on this file at startup (repairing wider modes) and refuses symlinked log paths — logs carry peer IPs and topology |
| `-log-file-max-mb` | `10` | Max log file size in MB before rotation (0 disables rotation) |
| `-log-file-max-backups` | `5` | Max rotated log files to keep (`0` keeps all of them — pair with `-log-file-max-age` so the directory cannot grow forever) |
| `-log-file-max-age` | `28` | Max days to keep rotated log files |
| `-svc` | `""` | Windows service action: `install`, `uninstall`, `start`, `stop`, `run` |
| `-echo-secret` | `""` | HMAC secret authenticating UDP probes (env `LINK_PING_ECHO_SECRET`; must be set on **both** client and server — a server without it accepts the client's HMAC frame as a plain payload probe, see [Wire Protocol](#wire-protocol); expands the wire frame to 32 bytes) |
| `-echo-secret-old` | `""` | Server: previous HMAC secret still accepted during a zero-downtime rotation, alongside `-echo-secret` (env `LINK_PING_ECHO_SECRET_OLD`; server side only) |

**Why MTU discovery (`-mtu-sweep`) matters:** 24-byte probes prove a path *exists* — they cannot prove it *carries full-size traffic*. VPN tunnels, PPPoE/GRE/VXLAN overlays and broken PMTUD routinely pass small packets while black-holing full-size ones — the classic "monitor says healthy, users say broken" failure. The sweep DF-marks probes on a dedicated socket, binary-searches the largest frame that round-trips, and publishes it as `link_path_mtu_bytes`; a shrinking gauge (or rising `link_mtu_probes_lost_total` while `link_up` stays 1) is that failure's signature. A size with no echo is retried once before the search shrinks — a single dropped probe on a lossy path would otherwise converge far below the real MTU and make the gauge flap between sweeps — so both MTU counters advance per attempt and read as a probe rate, not one probe per distinct size tested. It needs no ICMP and no extra firewall rules, uses separate counters that never enter the loss ratio, and is on by default (1m; `0` disables). Alert on `link_path_mtu_bytes < max_over_time(link_path_mtu_bytes[24h])`, or
on MTU probe loss as a RATIO (`rate(link_mtu_probes_lost_total[10m]) /
rate(link_mtu_probes_sent_total[10m]) > 0.2`) — a bare `> 0` fires on a
single retried probe, which a normal 1%-loss path produces routinely. `link_up`
deliberately stays 1 through an MTU shrink (24-byte probes keep flowing), so
the gauge — not `link_up` — is the MTU-specific alarm.

Liveness endpoints `GET /healthz` and `GET /readyz` on the same metrics listener return `200 ok` (`text/plain`) for Kubernetes/container probes. They are deliberately unauthenticated — only `/metrics` and `/status` are gated — and are available over both HTTP and HTTPS. `/healthz` is always 200; `/readyz` returns `503` while a client-mode agent has no target with a working socket (server-only mode is always 200), so a rollout waits for a real link. `/metrics` itself serves at most 2 concurrent scrapes — a third concurrent request gets `503`, and responses are bounded by a 30s write timeout — so a scrape storm cannot multiply gather trees against `GOMEMLIMIT`.

`GET /status` on the same listener serves a JSON snapshot of live per-target probe state — `link_up`, in-flight probes, consecutive misses, the current consecutive send-failure streak (`send_failures`, reset on any successful write; not a cumulative count), RTO/SRTT, last sequence number, socket age, `path_mtu_bytes` (largest DF frame proven to round-trip; 0 = no successful sweep yet) and `last_echo_age_seconds` (-1 until the first echo) — for debugging a flapping target without log access. It also returns a `process` object with Go runtime memory and GC stats — `heap_alloc_bytes`, `heap_sys_bytes`, `heap_idle_bytes`, `heap_released_bytes`, `stack_inuse_bytes`, `gc_sys_bytes`, `sys_bytes`, `gc_count` and `goroutines` — so heap growth is observable remotely without a debugger. Unlike the health endpoints it is auth-gated exactly like `/metrics` (open only when no metrics auth is configured). The `process` snapshot is re-read at most once per second (`runtime.ReadMemStats` stops the world and `/status` is uncapped), so a burst of requests cannot inject pauses into the probe loop that inflate its own RTT samples.

Resource footprint: metric handles are resolved once per target at startup (no per-probe label lookups), and the Go heap is soft-capped at 128MB (`GOMEMLIMIT` env overrides) so RSS stays flat on long runs. For >100 targets set `GOMEMLIMIT=256MiB` (or higher) as a system environment variable and restart the service.

### Memory & Runtime Tuning

`GOMEMLIMIT` keeps its 128MiB default when the env var is unset; `GOGC` is left at Go's own default (100). Both remain env-overridable. A binding `GOMEMLIMIT` does not reduce the footprint of an idle agent — the runtime only reacts as the heap approaches the limit — so treat it as a safety valve for large target counts, not a footprint knob.

Every `/metrics` scrape allocates (gather trees, text encoding, optional gzip) and ratchets Go's heap high-water mark upward; the runtime does not return it while the agent is otherwise idle because scavenging is allocation-rate driven. On Windows the visible number is commit/working set, so this ratchet shows up there as steady growth.

`-mem-scavenge` (default `5m`, `0` disables) forces a scavenge on that interval so the high-water mark goes back to the OS; it is skipped unless at least 4MB of *releasable* heap is held (`HEAP_IDLE - HEAP_RELEASED`), the figure the scavenge can actually return, not total process memory — an already-lean process pays nothing. `/status` exposes the same picture as its `process` object for observing it remotely.

`GOGC` is the other lever, and the right value depends on the scrape load (both measured on one target):

- A bursty load (800 scrapes back to back) ended at `heap_sys` 14.7MB / total 22.5MB by default, versus 6.8MB / 14.4MB with `GOGC=50`, for ~0.8ms extra CPU per scrape.
- A quiet agent (sparse scrapes) measured *worse* at `GOGC=50`: RSS 19.8MB vs 16.7MB, `gc_sys` 2.77MB vs 1.47MB, and ~5x the allocation churn, because it GCs a small heap more often.

So set `GOGC=50` for scrape-heavy deployments and leave it unset (or raise it) for a quiet one. `GOMAXPROCS=1` was the lowest-footprint configuration measured (RSS 14.6MB vs 16.7MB) at the cost of GC parallelism.

`-metrics-gzip` is off by default for the same reason: `promhttp` pools one gzip writer per CPU and each writer holds a `flate` compressor of roughly 0.7MB (`hashHead` 1<<17 + `hashPrev` 1<<15 plus a 32KB window), so compression can retain up to ~0.7MB x `GOMAXPROCS` of live heap across scrapes — more than the entire `/metrics` body of a small fleet. Measured with 400 plain versus 400 compressed scrapes on one target: live heap 1.24MB vs 3.98MB and `heap_sys` 10.8MB vs 14.7MB. Enable it (`-metrics-gzip=true`) when the response is large enough for the bandwidth saving to matter.

### Targets File

JSON file with an array of `{"name": "...", "address": "host:port"}` objects. Optional per-target `interval`/`timeout` override the global `-interval`/`-timeout` (duration strings like `"500ms"`, `"1s"`; 0 or absent means use global):

```json
[
  {"name": "server1", "address": "192.168.1.10:4000"},
  {"name": "server2", "address": "192.168.1.11:4000", "interval": "200ms", "timeout": "800ms"}
]
```

Max 1000 targets, max file size 1 MB. Per-target interval/timeout must be >0 when set; `interval >= timeout` warns (global and per-target) and `reconnect-interval < interval` is an error.

**Address syntax:** `address` is `host:port` with the port in 1-65535, checked syntactically at load time (no DNS lookup, so a reload never depends on the network). Two dialable forms go beyond plain RFC 1123 name labels: a DNS name may carry one trailing dot for the FQDN root (`mon.example.com.:5000`), and an IPv6 literal may carry a `%zone` scope suffix whose characters are letters, digits, `_`, `-` and `.` so VLAN interface names work (`[fe80::1%eth0.100]:5000`). A zone on a DNS name or an IPv4 literal is rejected (`example.com%eth0:80`, `1.2.3.4%eth0:80`), and so is a trailing dot on an IP literal (`1.2.3.4.:80`) — the root dot is only stripped from names.

**Hot reload:** send `SIGHUP` to re-read the file without a restart (Unix), or run with `-targets-reload-interval` (e.g. `30s`) for automatic polling — the only option under a Windows service, which has no SIGHUP. On reload: new targets start probing, removed targets stop and their series are deleted from `/metrics` (Prometheus marks the vanished series stale, so `link_up`-keyed alerts stop firing for them — an `absent()`/`up` alert covers a fully dead client), and targets whose address/intervals changed restart with the new values. A file that is mid-edit or invalid keeps the previous set running — reload failures are logged at Error level, never fatal. A reload whose file parses to an empty array logs a warning that all probing has stopped. A probe loop that fails to join within 5s is left stopped (its socket may still be draining) and its series are purged once it does exit, so a stuck loop cannot leave a frozen `link_up=1` behind.

### Examples

Client (single target):

```sh
./link_ping_prometheus -mode=client -target="192.168.1.71:4000" -metrics=":2112"
```

Client (multiple targets):

```sh
./link_ping_prometheus -mode=client -targets=targets.json -metrics=":2112"
```

Server:

```sh
./link_ping_prometheus -mode=server -listen=":4000" -allow=192.168.1.71 -metrics=":2112"
```

Both:

```sh
./link_ping_prometheus -mode=both -targets=targets.json -metrics=":2112"
```

## Installation

### Service

#### Windows

Use `-svc` to install/uninstall/start/stop/run. The tool records runtime flags at install time (excluding `-svc`, `-metrics-user`, `-metrics-pass`, `-echo-secret`, and `-echo-secret-old`). Metrics auth credentials and HMAC secrets are **not** persisted into the service configuration; set `LINK_PING_METRICS_USER` / `LINK_PING_METRICS_PASS` and `LINK_PING_ECHO_SECRET` / `LINK_PING_ECHO_SECRET_OLD` in the service environment instead (a warning is printed at install time).

```sh
link_ping_prometheus.exe -mode=both -targets=targets.json -metrics=":2112" -log-file="C:\ProgramData\link_ping_prometheus\logs\service.log" -svc=install
```

**Built-in service hardening (configured automatically at install):**

- **Crash recovery**: SCM failure action is *restart* after 5s (reset period 24h). A crash or fatal internal error exits non-zero so recovery fires — a dead monitor never stays down silently.
- **Delayed auto-start** with dependencies on `Tcpip` (sockets) and `W32Time` (time sync — the HMAC replay window requires roughly NTP-synchronized clocks between nodes).
- **Lifecycle events in the Windows Event Log** (Application source `link_ping_prometheus`): start, stop, and fatal errors are visible even with no access to the log file.
- **Credentials never persisted** into the service configuration.

**Windows Server version support:** the agent runs as a service on any Windows the Go runtime supports; SCM recovery, log rotation, HMAC and the UDP echo path have no version-specific requirements. The optional `-mtu-sweep` DF discovery supports IPv4 targets on every Windows Server version (Server 2003+ via the classic `IP_DONTFRAGMENT` option, falling back from the richer `IP_MTU_DISCOVER` path-MTU option available on Server 2019+/Windows 10 1703+); IPv6 targets need Windows Server 2019+ (or Windows 10 1703+). On Windows versions lacking a needed option the sweep alone disables itself with a one-time warning — probing is unaffected.

**Enterprise deployment checklist:**

> `installer/windows/install-service.bat` / `uninstall-service.bat` in this repo automate steps 1–4 below (admin check, ACL'd log dir, escalating restart ladder, per-service SID, credential prompts). Run from an elevated prompt: an interactive wizard asks for mode (server/client/both), metrics address, targets — a JSON file or a single host:port — the **required** client IP allow-list for server/both modes, log directory, and optional service account, then shows a summary before installing.

1. **Always pass `-log-file` at install.** Under the service, stdout is discarded; without a log file, verbose logs go nowhere (lifecycle/fatal events still reach the event log). Log rotation is built in (`-log-file-max-mb/-backups/-age`). A warning is printed if you skip it. The agent enforces `0600` on the log file at startup (repairing wider modes) and refuses symlinked log paths — place the log in a directory not writable by other local users (the installer's ACL'd log dir satisfies this).
2. **Service account.** By default the service installs as `LocalSystem`, which is more privilege than this prober needs (outbound UDP + a metrics port + its log directory). For least privilege, switch to a passwordless built-in or gMSA account after install:

   ```sh
   sc.exe config link_ping_prometheus obj= "NT AUTHORITY\LocalService"
   ```

   Use `NT AUTHORITY\NetworkService` instead of LocalService if network firewalls expect machine-account identity, or a domain gMSA (`DOMAIN\svc-linkping$`) if policy mandates managed accounts. Grant the chosen account write access to the log directory only.
3. **Secrets delivery.** Set the credential environment variables machine-wide via System Properties → Environment Variables, or per-service:

   ```sh
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_METRICS_USER /t REG_SZ /d <user> /f
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_METRICS_PASS /t REG_SZ /d <pass> /f
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_ECHO_SECRET /t REG_SZ /d <secret> /f
   ```

   Be aware: that registry key is readable by all local users by default — treat these values as non-secret-grade, restrict who can log on to the host, and prefer an ACL-hardened secrets file sourced by your config management for higher assurance. Restart the service after changing them. Tighten the ACL on that `Environment` key so only SYSTEM, Administrators and the service account can read it, and rotate the values on a schedule — they sit in the registry in plaintext for the life of the install.
4. **Further hardening (optional, post-install):** restart escalation ladder via `sc.exe failure link_ping_prometheus reset= 86400 actions= restart/5000/restart/30000/restart/60000`; restrict who can reconfigure the service via `sc.exe sdset`; give the service a per-service SID (`sc.exe sidtype link_ping_prometheus unrestricted`) and ACL the log/data directories to it; keep the binary under `%ProgramFiles%` with Admins-only write ACLs; Authenticode-sign the binary and allowlist via AppLocker/WDAC.
5. **Upgrades:** re-run `installer/windows/install-service.bat` with the new binary — it detects the existing service, swaps the binary only when its SHA256 differs, and restarts (runtime truth updates via `link_ping_build_info`). Parameters are preserved. If any runtime flags changed, uninstall and reinstall instead — arguments are snapshotted at install time. Verify the release checksum (and the signature, once releases are signed) before running the installer: this step is elevated and writes a service, so a tampered binary lands with SYSTEM rights.
6. **Supply chain and fleet-wide auth, before scaling out:**
   - Restrict who can create `v*` tags with a GitHub Ruleset — the release build reads the tag for `link_ping_build_info`, so tag creation is a release-authoring permission, not a general contributor one.
   - Pin the WinRM CA per host in the Ansible inventory (`deploy/ansible/inventory.example.yml`); an unpinned `winrm` connection trusts whatever CA answers first, which is the deploy host's supply chain.
   - Clock sync is load-bearing, not hygiene: `-echo-secret` rejects any probe more than 30s from the reflector's clock, so a drifted node drops its own legitimate probes as replay and its peers read `link_up=0`. `LinkClockSkewHigh`, `LinkClockSkewCritical` and `ServerReplayDrops` in `rules/link-monitor.yml` alert on it — load them everywhere the service runs.

#### Linux (systemd)

Create `/etc/systemd/system/link_ping_prometheus.service`:

```ini
[Unit]
Description=Link Ping Prometheus (UDP link monitor)
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
ExecStart=/usr/local/bin/link_ping_prometheus -mode=server -listen=":4000" -allow=203.0.113.5 -metrics=":2112"
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

`time-sync.target` ordering is load-bearing: with `-echo-secret` set the
server's replay guard uses a 30s timestamp window, so clocks must be
roughly NTP-synchronized. Note: In client/both mode, use an absolute path
for `-targets` (e.g., `-targets=/etc/link_ping_prometheus/targets.json`).

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now link_ping_prometheus
```

## Deployment (Ansible)

For fleets, `deploy/ansible/playbook.yml` deploys the pre-built binary
and service definition to remote Linux (systemd, using
`installer/linux/link_ping_prometheus.service` — the hardened unit, driven
by `/etc/link_ping_prometheus.env`) and Windows (SCM via `sc.exe`, with the
same failure-recovery ladder as `main.go`) hosts. Secrets are delivered via
the service environment on both platforms — never service arguments, and
the secret-bearing tasks are marked `no_log` so they cannot leak into
`-v`/`--diff` output. See `deploy/ansible/README.md` for prerequisites and
usage.

## Grafana Dashboard

Prebuilt dashboard at [grafana-dashboard.json](grafana-dashboard.json).
It uses the Grafana v2 dashboard resource format
(`dashboard.grafana.app/v2`) and needs a Grafana version that supports it;
it also has a `source` variable for filtering panels per site.

Panels: link status, packet loss, RTT percentiles / average / current, adaptive RTO, jitter, probe throughput, plus the newer signals — smoothed RTT (SRTT), path MTU (DF-probed), DF probe loss, corruption % (with `-payload`) and send errors (local fault vs network loss). A **Server & prober health** section covers probes in flight, server probes received / dropped by reason / echo errors, clock skew, prober internal errors and metrics auth failures. `link_up` transitions are annotated on every panel and itemized with timestamps in the Link State Changes table. The `source` variable filters the per-site panels, so one dashboard serves the whole fleet (the global metrics-auth-failure panel is deliberately unfiltered).

[![Grafana dashboard screenshot](.docs/screenshot01.png)](.docs/screenshot01.png)

## Code Structure

```text
main.go                     — CLI wrapper, flag parsing, service lifecycle
main_test.go                — lifecycle race, auth/TLS flag validation tests
main_metrics_test.go        — /metrics body decoding (gzip on/off)
internal/prober/
  prober.go                 — Config, protocol constants, HMAC helpers, pending-window cap
  adaptive.go               — RFC 6298 RTO estimation (AdaptiveStats)
  client.go                 — Target, LoadTargets, RunClient, UDP probe loop
  server.go                 — UDP echo responder, allowlist, rate limits, client series
  metrics.go                — Prometheus metric vars, InitMetrics, MetricsAuth
  status.go                 — /status registry (target snapshots + process memory)
  validate.go               — Target address validation (ValidateTarget)
  mtu.go                    — DF path-MTU sweep (shared search + state)
  mtu_linux.go              — IP_MTU_DISCOVER/IPV6_MTU_DISCOVER socket option
  mtu_windows.go            — Windows PMTUD with an IP_DONTFRAGMENT fallback ladder
  mtu_other.go              — sweep disabled on platforms without a DF option
  dscp_linux.go             — DSCP marking (IP_TOS/IPV6_TCLASS)
  dscp_other.go             — no-op elsewhere
  unreachable_other.go      — ICMP-derived read errnos (Unix)
  unreachable_windows.go    — ICMP-derived read errnos (winsock codes)
  adaptive_test.go          — RTO estimation, dynamic floor, backoff clamp
  client_recovery_test.go   — reader death, panic restart, write failure, dial retry
  client_retry_test.go      — dial failure retry, send-error accounting
  client_straggler_test.go  — reload stragglers: restart when wanted, purge when removed
  client_hmac_test.go       — client-side HMAC frames and the HMAC+payload offset
  validation_test.go        — Config/target validation incl. the pending-window cap
  allowlist_test.go         — allowlist parser accepts and rejects
  unreachable_test.go       — peer-unreachable classification (Unix)
  unreachable_windows_test.go — same for winsock codes
  mtu_linux_test.go         — DF socket option applied to a v4 socket
  dscp_test.go              — DSCP socket option
  validate_dscp_test.go     — DSCP range validation
  bench_test.go             — resolve-once vs per-event label lookup, payload fill, allowlist
test/
  helpers_test.go           — Test utilities (metric inspectors, UDP echo server)
  adaptive_test.go          — AdaptiveStats logic and jitter adaptation
  validation_test.go        — LoadTargets, target parsing, Config validation
  server_test.go            — Server garbage handling, rate limits, allowlist, eviction
  client_test.go            — Robustness: loss, latency, corruption, spoofing, stalls, duplicates
  metrics_test.go           — Basic auth handler, metric seeding
  integration_test.go       — Multi-target, server dropout, stress (10 targets)
  accuracy_test.go          — Balance invariant, bucket placement, jitter ceiling, loss deadline
  precision_test.go         — Exact analytic assertions (RTO floor, jitter convergence)
  jitter_test.go            — RFC 3550 convergence, reset on gap, rebuild
  mtu_test.go               — Path-MTU sweep and its separate counter namespace
  payload_test.go           — Corruption detection, counted apart from loss
  reload_test.go            — Hot reload: purge removed, keep changed, /status parity
  status_test.go            — Live /status snapshot contents, process object, cache
  timeout_override_test.go  — Per-target interval/timeout overrides
  soak_test.go              — Opt-in memory/goroutine soak (SOAK_SECONDS)
```

## Wire Protocol

UDP datagram, 24 bytes per probe (32 bytes when `-echo-secret` is set on
both ends, plus an optional payload extension when `-payload` is set on
the client):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Magic header `LNKPING\x00` |
| 8 | 8 | Sequence number (little-endian uint64) |
| 16 | 8 | Client timestamp (Unix ns, little-endian uint64) |
| 24 | 8 | HMAC-SHA256 tag (first 8 bytes; only with `-echo-secret`) |
| 24/32 | ≤1400 | Optional pattern payload (only with `-payload`): deterministic bytes derived from seq/ts, validated byte-for-byte by the client on echo. |

The server validates the magic header and accepts the header frame plus
any bounded payload extension (header ≤ size ≤ header + 1400 bytes)
before echoing; anything smaller or larger is dropped silently. Payload
corruption is detected client-side and counted separately from loss. The client additionally
requires the echoed timestamp to exactly match the value it sent —
corrupted, replayed, or spoofed responses are discarded and counted as
loss on timeout, protecting RTT samples from poisoning.

`-echo-secret` must be set on **both** ends. A server running without it
cannot distinguish a 32-byte HMAC frame from a payload probe — 32 falls
inside the accepted `header ≤ size ≤ header + 1400` range — so it echoes
the frame unverified. A half-configured fleet therefore reads healthy with
no probe authenticated: nothing lands in
`link_server_probes_dropped_total{reason="hmac"}`, and the allowlist is the
only thing gating the reflector. The server logs a startup warning when
`-echo-secret` is unset.

The server rate-limits echo processing to 2000 packets/s per remote IP
and 10000 packets/s globally (fixed one-second window); excess datagrams
are dropped. The window is fixed, not sliding, so a burst straddling a
window boundary can admit up to 2× the cap — treat the caps as ceilings,
not a precise rate. The probe loop keeps a single connected UDP socket per
target, but re-dials every 5 minutes by default (`-reconnect-interval`, only when no probes are in flight)
so a target hostname that changes IP via DNS is re-resolved; a transient
DNS failure at startup is retried, not fatal.

## Security

- The UDP echo server validates the magic header and accepts the header
  frame plus any bounded payload extension (`header ≤ size ≤ header +
  1400`) before echoing it verbatim; out-of-range datagrams are dropped.
  Reflection is 1:1 — the echo is never larger than the probe, so the
  server is not an amplifier — and it rate-limits echo processing per
  source IP and globally. The allowlist is fail-closed
  (no `-allow`, no service) and accepts plain IPs or CIDR prefixes; plain
  IPs keep per-client metric series pre-resolved, while CIDR-matched
  clients are capped at 1024 distinct IPs per process (`client_overflow`
  drops beyond that) so spoofed source rotation cannot grow the label space.
  A sweeper inside the echo loop also expires CIDR-matched clients idle for
  the TTL (10 minutes by default) — on its own timer, so it runs whether or
  not the cap is reached and whether or not any other client is still
  probing. Eviction deletes the client's `link_server_probes_received_total`
  and `link_server_clock_skew_seconds` series, not just its slot: an idle or
  decommissioned peer stops exporting a frozen last value (a skew alert that
  could never resolve). If that client returns, its series are re-created at
  0, so a `rate()` window spanning the return sees a counter reset and
  understates that interval — the accepted cost of bounded cardinality.
  Exact-IP allowlist entries are never evicted; their handles and series are
  pre-resolved at startup.
- Echoed timestamps are validated exactly (see Wire Protocol), so off-path
  corruption and replays cannot fabricate RTT samples.
- With `-echo-secret` set, the server also rejects probes whose embedded
  timestamp is older or newer than ~30 seconds, so a captured probe cannot be
  replayed indefinitely with a spoofed source. This means both nodes must have
  roughly synchronized clocks — NTP is recommended on monitoring endpoints.
- `-echo-secret` only protects the link when **both** ends set it. A server
  without it accepts the client's 32-byte HMAC frame as a bounded payload
  probe and echoes it back, so the client reads a healthy link with no
  `hmac` drop reason and no reflector authentication — the allowlist is then
  the only control. The server logs a startup warning when the secret is
  unset; a partially-configured fleet is exactly what that warning surfaces.
- Secret rotation without an outage: with the old secret in the service
  environment of every endpoint, restart the SERVERS with
  `-echo-secret=<new>` plus `-echo-secret-old=<old>` (or
  `LINK_PING_ECHO_SECRET` + `LINK_PING_ECHO_SECRET_OLD`) so frames from
  clients still on either secret are accepted. Then restart the clients
  with `-echo-secret=<new>`. Finally remove `-echo-secret-old` from the
  servers — any frame failing both secrets still counts in
  `link_server_probes_dropped_total{reason="hmac"}` so a half-rotated
  fleet is visible in metrics.
- UDP is not amplification-prone (echo is the same size as the request)
  and carries no state, but any internet-facing echo endpoint should be
  firewall-restricted to known monitoring sites.
- The `/metrics` endpoint supports HTTP Basic Auth (`-metrics-user` / `-metrics-pass`) with constant-time comparison over hashed credentials. Both must be set together; the process refuses to start with only one.
- Prefer the `LINK_PING_METRICS_USER` / `LINK_PING_METRICS_PASS` environment variables over CLI flags — flag values are visible in `ps` to other local users.
- Basic Auth without TLS sends credentials as base64 on the wire; a startup warning is logged in that configuration. Use `-metrics-tls-cert` / `-metrics-tls-key` to serve `/metrics` over HTTPS.
- The wire protocol carries no sensitive data (sequence numbers and wall-clock timestamps only) and has no TLS — intended for internal network monitoring. Restrict access with a firewall on untrusted networks.

## Contributing

Bug reports and pull requests are welcome. Before opening a PR:

```sh
go build ./... && go vet ./... && go test -count=1 -race ./...
```

The integration tests run real UDP traffic on `127.0.0.1` and take a few
minutes. Keep changes one logical commit each (Conventional Commits style:
`feat:`, `fix:`, `docs:`). If a change touches metrics, flags, or constants,
update the README table in the same PR — docs and code drift together.

## License

[GPL-3.0](LICENSE)
