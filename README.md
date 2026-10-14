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

## Documentation

Full guides live in [`docs/`](docs/README.md):

- **Deployment** — [Windows service](docs/windows-service.md), [Linux systemd](docs/linux-systemd.md), [Docker](docs/docker.md), [Ansible](docs/ansible.md), [N-site mesh](docs/mesh-deployment.md)
- **Configuration** — [targets file](docs/targets-file.md), [operations and tuning](docs/operations.md)
- **Monitoring** — [PromQL examples](docs/promql.md), [alert rules](docs/alerting.md), [scraping and dashboard](docs/scraping.md)
- **Internals** — [wire protocol](docs/wire-protocol.md), [security](docs/security.md), [development](docs/development.md)

## Quick start

Run the echo server on one node and the prober on the other. The server is
**fail-closed**: it refuses to start without `-allow` and echoes only the
client IPs listed there.

```sh
# Node A - echo server
./link_ping_prometheus -mode=server -listen=":4000" -allow=192.0.2.11 -metrics=":2112"

# Node B - probe Node A, tagging every series with the local site
./link_ping_prometheus -mode=client -target="192.0.2.10:4000" -source="site-b" -metrics=":2112"
```

Each configured target is one monitored link, so a link is only measurable
with an agent at **both** ends. Set `-echo-secret` on the client and the
server together: a server without it accepts the client's HMAC frame as a
plain probe and echoes it, so a half-configured fleet reads healthy while
nothing is authenticated. Then scrape both `/metrics` endpoints and open the
[bundled dashboard](grafana-dashboard.json).

Multi-arch images are published as
`ghcr.io/callumau/link_ping_prometheus` (`linux/amd64`, `linux/arm64`) - see
[Docker](docs/docker.md).

## Installation

| Platform | Guide |
| --- | --- |
| Windows Server | [Windows service](docs/windows-service.md) - `-svc=install`, SCM crash recovery, ACL'd log directory, Event Log lifecycle events |
| Linux (systemd) | [Linux systemd](docs/linux-systemd.md) - the hardened unit shipped in `installer/linux/` |
| Containers | [Docker](docs/docker.md) |
| Fleets | [Ansible](docs/ansible.md) - `deploy/ansible/playbook.yml` for Linux and Windows hosts |
| Multiple sites | [Mesh deployment](docs/mesh-deployment.md) - one shared targets file, allowlist derived from it |

Every option runs the same binary with the same flags; [deployment](docs/deployment.md)
covers how to choose, and clocks must be roughly NTP-synchronized on all nodes
because the HMAC replay window is +/- 30s.

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
| `-allow-from-targets` | `false` | Server: derive the fail-closed allowlist from the `-targets` file addresses and skip the target whose `name` equals `-source`, so **one** targets file serves every site of a mesh (still combinable with `-allow` for extra CIDRs). Every target address must be an IP literal — a DNS name is a startup error, because config load never resolves (a reload must not depend on the network). This removes the per-site allowlist: adding or renumbering a site becomes a one-line edit to the shared file, picked up by reload. See [Mesh deployment](docs/mesh-deployment.md). |
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
| `-metrics-user` | `""` | Basic auth username for /metrics (empty = disabled; env `LINK_PING_METRICS_USER`; must not contain `:` — HTTP Basic Auth splits at the first colon, so such a user is unreachable and startup is refused) |
| `-metrics-pass` | `""` | Basic auth password for /metrics (env `LINK_PING_METRICS_PASS`; prefer env over CLI to avoid `ps` exposure) |
| `-metrics-tls-cert` | `""` | TLS certificate file for /metrics (requires `-metrics-tls-key`) |
| `-metrics-tls-key` | `""` | TLS private key file for /metrics (requires `-metrics-tls-cert`) |
| `-metrics-allow-insecure` | `false` | Allow Basic Auth without TLS (otherwise auth over plaintext HTTP is rejected) |
| `-metrics-gzip` | `false` | Gzip-compress `/metrics` responses when the scraper offers it. Off by default because promhttp pools a gzip writer per CPU and each holds ~0.7MB of flate state, so compression costs up to ~0.7MB x `GOMAXPROCS` of live heap — more than a small fleet's whole response. Enable it for many targets. |
| `-mem-scavenge` | `5m` | Runtime: force a heap scavenge at this interval so the unused heap high-water mark is returned to the OS (0 disables; skipped unless at least 4MB of releasable heap is held, see [Memory & Runtime Tuning](docs/operations.md#memory-and-runtime-tuning)). |
| `-json-logs` | `false` | Output logs in JSON format |
| `-log-file` | `""` | Append logs to this file in addition to stdout (required for Windows service logging, where stdout is discarded). The agent enforces mode `0600` on this file at startup (repairing wider modes) and refuses symlinked log paths — logs carry peer IPs and topology. On Windows the equivalent DACL is applied for it: full access only to SYSTEM, Administrators and the service account, protected from parent inheritance |
| `-log-file-max-mb` | `10` | Max log file size in MB before rotation (0 disables rotation) |
| `-log-file-max-backups` | `5` | Max rotated log files to keep (`0` keeps all of them — pair with `-log-file-max-age` so the directory cannot grow forever) |
| `-log-file-max-age` | `28` | Max days to keep rotated log files |
| `-svc` | `""` | Windows service action: `install`, `uninstall` (Windows only; Linux deploys use the systemd unit), `start`, `stop`, `run` |
| `-echo-secret` | `""` | HMAC secret authenticating UDP probes (env `LINK_PING_ECHO_SECRET`; must be set on **both** client and server — a server without it accepts the client's HMAC frame as a plain payload probe, see [Wire Protocol](docs/wire-protocol.md); expands the wire frame to 32 bytes) |
| `-echo-secret-old` | `""` | Server: previous HMAC secret still accepted during a zero-downtime rotation, alongside `-echo-secret` (env `LINK_PING_ECHO_SECRET_OLD`; server side only; startup error if set without `-echo-secret`) |
| `-hmac-coverage` | `full-frame` | Client: which frame bytes the HMAC tag covers when `-echo-secret` is set. `full-frame` (default) tags the header plus the `-payload` bytes (tag slot skipped), so a tampered payload — or a different payload riding a captured tag — no longer authenticates; needs `-payload > 0` to differ from `header`. `header` (the v0.7 layout, byte-identical wire output) is the escape hatch for probing through a v0.7 echo server while using `-payload`. The echo server accepts BOTH coverages whenever it has `-echo-secret`; upgrading it to ≥ v0.8 clears the one broken pairing (v0.7 server + full-frame client). Invalid values are a startup error. |

The reasoning behind the MTU sweep, the `/metrics`, `/healthz`, `/readyz`
and `/status` endpoints, and the memory/runtime tuning knobs is in
[operations and tuning](docs/operations.md).

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
./link_ping_prometheus -mode=both -targets=targets.json -allow=192.168.1.71 -metrics=":2112"
```

### Targets file

JSON array of `{"name": "...", "address": "host:port"}`, with optional per-target
`interval`/`timeout` overrides (duration strings; 0 or absent means use the
global `-interval`/`-timeout`):

```json
[
  {"name": "site-a", "address": "192.0.2.10:4000"},
  {"name": "site-b", "address": "192.0.2.11:4000", "interval": "200ms", "timeout": "800ms"}
]
```

Max 1000 targets, max file size 1 MB. See the
[targets file guide](docs/targets-file.md) for the address syntax, hot reload,
and the one-file-for-a-whole-mesh pattern.

## Metrics

`/metrics` (default port 2112) exposes the series below. Two rules apply to
every counter: never divide raw totals - they accumulate forever, so wrap them
in `rate()` - and choose the rate window to match the shortest outage you want
to read as 100% loss. Worked queries are in [PromQL examples](docs/promql.md).

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
| `link_probes_throttled_total` | Counter | `source`, `target`, `address` | Probes skipped because the pending window (the timeout/interval ratio) is full: the adaptive RTO floor (`2×SRTT`) can exceed the configured timeout and grow the in-flight set past its cap, so sends are skipped until probes resolve. A probe-rate reduction, NOT network loss — a throttled probe is never built or sent and is not counted in `link_probes_sent_total`. |
| `link_prober_internal_errors_total` | Counter | `source`, `target`, `address`, `reason` | Prober-internal failures (`reason`: `panic`, `reader_dead`, `dial_retry`, `stop_timeout`) — not link conditions. A rising rate means this target's probe numbers are unreliable; check the agent's own logs and socket state. |
| `link_probes_inflight` | Gauge | `source`, `target`, `address` | Current number of probes sent but waiting for a response or timeout. Grows during stalls. |
| `link_rtt_seconds` | Histogram | `source`, `target`, `address` | RTT histogram with explicit buckets `{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 3.0}` s plus native histogram support (`NativeHistogramBucketFactor` 1.1). Buckets stop at 3s, the RTO cap: an echo that misses its RTO is normally counted as loss and discarded, so higher edges stay empty — except for the samples above 3s that can still occur: a link whose SRTT exceeds 1.5s applies a timeout above the cap (floor `2×SRTT`), a fixed `-timeout` above 3s does the same, and an echo that misses its RTO by up to one probe interval is still recorded (see the timeout row above). |
| `link_rtt_seconds_bucket/sum/count` | Histogram | `source`, `target`, `address` | Classic-bucket series; quantiles and means are derived in PromQL over any window. |
| `link_rtt_jitter_seconds` | Gauge | `source`, `target`, `address` | Smoothed RTT jitter in seconds (RFC 3550 §6.4.1). Resets to 0 on the first echo after a sequence gap (a timed-out probe), so link recovery never spikes the gauge; during a total outage it holds its last value until that echo. |
| `link_rto_seconds` | Gauge | `source`, `target`, `address` | Current adaptive RTO in use (RFC 6298, doubled on consecutive timeouts; floor `max(200ms, 2×SRTT)`). The 3s cap bounds the backoff value, **not** the floor: a link whose SRTT exceeds 1.5s applies a timeout above 3s, deliberately, or it would be read as loss. |
| `link_rtt_srtt_seconds` | Gauge | `source`, `target`, `address` | Smoothed RTT estimate (RFC 6298 SRTT), a window-independent latency signal for dashboards and baseline-shift alerts. Stays 0 with adaptive mode disabled. |
| `link_server_probes_received_total` | Counter | `source`, `client` | Valid probes received by the server, per remote client IP (server mode only). Cross-check against the client's sent counter — mismatches may also be echo write failures, see `link_server_echo_errors_total`. Includes MTU-sweep probes (they carry the same header frame), so subtract `rate(link_mtu_probes_sent_total)` before reading a mismatch as wire loss. A CIDR-matched client idle past the server's TTL loses this series and restarts it at 0 on return — see Security. |
| `link_server_echo_errors_total` | Counter | `source` | Validated probes the server failed to echo back (local UDP write error). The client counts these as loss, so subtract this rate before attributing a received/sent mismatch to the network. |
| `link_server_probes_dropped_total` | Counter | `source`, `reason` | Probes dropped by server: `allowlist`, `rate_ip`, `rate_global`, `size`, `magic`, `hmac`, `replay`, `dup`, `invalid_addr`, `client_overflow`. `dup` marks a frame identical to one recently echoed (same source, seq, timestamp) — replay or echo-loop guard, so two mutual-allowlist servers cannot bounce a frame forever; `hmac`/`replay` diagnose secret/NTP misconfig vs true loss; `client_overflow` means more distinct CIDR-allowlisted client IPs than the per-client series cap; that cap is not the only way a per-client series ends — CIDR-matched clients idle past the server's TTL have their series deleted and restart at 0 if they return (see Security). |
| `link_server_clock_skew_seconds` | Gauge | `source`, `client` | Last observed clock skew (server minus client timestamp) for HMAC probes; positive means client behind. Diagnose replay drops from NTP drift per peer. |
| `link_server_unauth_hmac_frames_total` | Counter | `source` | HMAC-shaped frames (32-byte header, with or without the bounded payload extension) received by a server running WITHOUT `-echo-secret`. They are still echoed as ordinary bounded payload probes — acceptance is unchanged — so this is the only signal a half-configured pairing (secret on clients, absent on the server) produces; a rising rate means set `-echo-secret` on **both** ends. A secret-less probe with a 24-byte header plus exactly 8 bytes of payload has the same shape and counts too. |
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

## Prometheus and Grafana

Scrape each node's `/metrics`, locally or remotely with `-metrics-user` /
`-metrics-pass` plus TLS. The series above feed ready-made queries, alerts and
the bundled dashboard:

- [PromQL examples](docs/promql.md) - loss, latency, jitter, baseline shift, link status, outages
- [Alert rules](docs/alerting.md) - the shipped `rules/link-monitor.yml` and dead-source coverage
- [Scraping](docs/scraping.md) - Prometheus scrape config, Grafana Alloy, and [grafana-dashboard.json](grafana-dashboard.json)

## Building

```sh
go build ./...          # Linux
./dev_build.sh          # Linux + Windows binaries into build/
go test -count=1 ./...  # integration tests run real UDP on 127.0.0.1
```

See [development](docs/development.md) for the test suite layout, CI checks and
code structure.

## License

[GPL-3.0](LICENSE)
