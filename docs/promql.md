# PromQL Examples

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
| **True wire loss** (needs server at remote end) | `100 * (1 - (sum(rate(link_server_probes_received_total{client="<ip>"}[$__rate_interval])) - sum(rate(link_mtu_probes_sent_total{target="<target>"}[$__rate_interval]))) / sum(rate(link_probes_sent_total{target="<target>"}[$__rate_interval])))` — `sum()` is required (disjoint label sets; see below) | % |

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
latency instead of loss; see the [`link_probes_timed_out_total`](../README.md#metrics) row).
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
the loss ratio meaningful. Because the floor is unbounded above (a
satellite-scale SRTT applies an RTO above the 3s cap), a fast `-interval`
especially on such a link can grow the in-flight window past its cap; the
loop then skips sends until probes resolve. Skipped probes are counted in
`link_probes_throttled_total` — a probe-rate reduction, not loss: they are
never built or sent, so neither `sent` nor the loss ratio is affected.

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
