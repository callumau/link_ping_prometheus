# Alert Rules File

The [alerts above](promql.md#outage-alerts) ship ready-to-load in
`rules/link-monitor.yml`: recording rules (`link:loss_ratio`,
`link:rtt_seconds_p50/p90/p99`, `link:mean_rtt_seconds`,
`link:rtt_seconds_p50_24h_min`, with matching `rate()` windows) and
alerting rules (`LinkDown`, `LinkMonitorAbsent`, `LinkScrapeTargetDown`,
`LinkMonitorSourceAbsent`, `HighPacketLoss` 5%/10m, `SeverePacketLoss` 20%/5m,
`LinkProbesStalled`, `LinkProbeStall`, `ProbeCorruption`, `ClientSendErrors`,
`ProberInternalErrors`, `MetricsAuthFailures`, `ServerDropsObserved`,
`ServerEchoErrors`, `LinkClockSkewHigh` >20s, `LinkClockSkewCritical` >25s,
`ServerReplayDrops`, `LinkLatencyDegraded`, `PathMtuDropped`,
`MtuProbeLossHigh` >0.2, `MtuSweepUnresolved`). Load them:

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/link-monitor.yml
```

Thresholds are starting points; tune per link.

`ServerReplayDrops` fires on replay drops while `link_up` is still 1.
`ProberInternalErrors`, `ServerEchoErrors`, `ProbeCorruption` and
`MetricsAuthFailures` flag prober-local failures: while
`link_prober_internal_errors_total` or `link_server_echo_errors_total` rises,
that target's loss ratio is unreliable.

### Dead-Source Coverage

`LinkMonitorAbsent` is a global catch-all: `absent(link_up)` fires only when
*every* `link_up` series is gone.

With more than one source, one dead prober leaves the others exporting and
**nothing fires**. Three shipped mechanisms close the gap:

1. **`LinkScrapeTargetDown`** (direct scraping): `up{job="link_ping"} == 0` for
   3m, carrying `job`/`instance` labels. The Prometheus job name must match the
   one this rule uses (`link_ping`), or the rule is inert.
   - Not available in remote-write (Alloy) setups: no `up` there.
2. **`LinkMonitorSourceAbsent`** (template in `rules/link-monitor.yml`, one rule
   per monitored source): `absent_over_time(link_up{source="site-a"}[10m])`.
3. **`LinkMonitorAbsent`** stays as the global fallback for single-source
   deployments and config-wide breakage. Do not load the file for
   `-mode=server` scrape jobs: `link_up` does not exist there and the alert
   fires forever.

#### Why one rule cannot see one dead source

Alert expressions evaluate per label set. When a prober stops exporting, its
`link_up` series goes stale ~2 scrape intervals later and vanishes from instant
evaluation.

Every `link_up`-keyed expression then returns an *empty vector* for that
source's labels, so firing alerts **resolve silently** and rate/threshold alerts
cannot see 0. `absent(link_up)` helps only when the selector matches **zero
series globally**, which a fleet never does.

Worked example — sources `sydney-dc` and `london-dc`, 1m scrape interval,
sydney dies at T:

| time | what happens |
| ------ | -------------- |
| T | sydney stops exporting `link_up` |
| ~T+2m | sydney's series goes stale; its alerts resolve or see empty vectors |
| any time | `LinkMonitorAbsent` stays quiet — london still exports, so the selector is never globally empty |
| ~T+11–12m | sydney's rule: `absent_over_time(link_up{source="sydney-dc"}[10m])` returns one series and fires |

Without a per-source rule, the third row stays final: **no alert at all**. The
`[10m]` window encodes the duration, so a `for:` would only delay the fire to
15m.

#### Recommended alert setup

Duplicate the `LinkMonitorSourceAbsent` template once per source (the shipped
file has no real source names — generate these from your inventory):

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

- The **equality matcher** is load-bearing: `absent_over_time` copies equality
  matchers' labels onto the synthetic series, so `{{ $labels.source }}` resolves
  to the dead source. A regex matcher (`source=~"sydney-.*"`) produces an
  unlabeled `{}` series that still fires only when *all* matching sources go.
- A source without its own rule has **no** dead-source coverage in remote-write
  deployments — adding a target means adding its rule.
- Direct-scrape deployments also get `LinkScrapeTargetDown` (~T+3–5m);
  remote-write setups rely on the per-source rules alone.
- Validate after generating: `promtool check rules rules/link-monitor.yml`.
