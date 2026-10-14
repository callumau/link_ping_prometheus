# Alert Rules File

The [alerts above](promql.md#outage-alerts) ship ready-to-load in `rules/link-monitor.yml`: recording
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
points — tune per link as with the [expressions above](promql.md#outage-alerts).

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
