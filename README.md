# Link Monitor (UDP Ping Prometheus Exporter)

Point-to-point link monitor for Prometheus, written in Go: active UDP echo
probes measure RTT, packet loss and jitter with an RFC 6298 adaptive timeout.
Run one agent per node; each configured target is one monitored link. **Why
UDP:** nothing is retransmitted, so a probe without an echo inside its
timeout is true network loss; TCP probing hides loss as inflated RTT.

## Documentation

Full guides live in [`docs/`](docs/README.md):

- **Deployment** — [Windows service](docs/windows-service.md),
  [Linux systemd](docs/linux-systemd.md), [Docker](docs/docker.md)
  (`ghcr.io/callumau/link_ping_prometheus`), [Ansible](docs/ansible.md),
  [mesh](docs/mesh-deployment.md)
- **Configuration** — [targets file](docs/targets-file.md),
  [operations and tuning](docs/operations.md)
- **Monitoring** — [PromQL](docs/promql.md), [alert rules](docs/alerting.md),
  [scraping](docs/scraping.md)
- **Internals** — [wire protocol](docs/wire-protocol.md),
  [security](docs/security.md), [development](docs/development.md)

## Quick start

Run the echo server on one node, the prober on the other. The server is
fail-closed: without `-allow` it refuses to start, and it echoes only the
listed client IPs. Set `-echo-secret` on both ends: a server without it
accepts the client's HMAC frame as a plain probe and echoes it, so a
half-configured fleet reads healthy unauthenticated.

```sh
# Node A - echo server
./link_ping_prometheus -mode=server -listen=":4000" -allow=192.0.2.11 -metrics="127.0.0.1:2112"

# Node B - probe Node A, tagging every series with the local site
./link_ping_prometheus -mode=client -target="192.0.2.10:4000" -source="site-b" -metrics="127.0.0.1:2112"
```

Then scrape both `/metrics` endpoints and open the
[bundled dashboard](grafana-dashboard.json).

## Installation

| Platform | Guide |
| --- | --- |
| Windows Server | [Windows service](docs/windows-service.md) — `-svc=install`, SCM crash recovery, ACL'd logs |
| Linux (systemd) | [Linux systemd](docs/linux-systemd.md) — hardened unit in `installer/linux/` |
| Containers | [Docker](docs/docker.md) |
| Fleets | [Ansible](docs/ansible.md) — `deploy/ansible/playbook.yml` |
| Multiple sites | [Mesh deployment](docs/mesh-deployment.md) — one targets file, allowlist derived from it |

Every option runs the same binary and flags;
[deployment](docs/deployment.md) covers choosing one. Synchronize clocks on
every node: the HMAC replay window is ±30s.

## Usage

```sh
link_ping_prometheus -mode=<mode> [flags]
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-mode` | `server` | Operation mode: `server`, `client` or `both` |
| `-listen` | `:4000` | Server: UDP listen address |
| `-allow` | `""` | Server: fail-closed client IP allowlist — IPs or CIDRs like `203.0.113.0/24`; max 256 |
| `-allow-from-targets` | `false` | Server: derive the allowlist from `-targets`, skipping the target named by `-source` |
| `-target` | `""` | Client: single target `host:port` |
| `-targets` | `""` | Client: path to a JSON targets file |
| `-metrics` | `127.0.0.1:2112` | Metrics listener; localhost-only by default (`:2112` exposes it — firewall-restrict) |
| `-interval` | `500ms` | Client: probe interval (warns when `>= -timeout`: probes queue) |
| `-timeout` | `1s` | Client: base/initial probe timeout |
| `-reconnect-interval` | `5m` | Client: socket lifetime before re-dialing for DNS re-resolution |
| `-dscp` | `0` | Client: DSCP mark 0-63 on probes (46 = EF); best effort, Linux |
| `-payload` | `0` | Client: bytes beyond the header, up to 1400; a deterministic pattern validated on echo |
| `-targets-reload-interval` | `0` | Client: poll the `-targets` file and apply changes without a restart |
| `-mtu-sweep` | `1m` | Client: sweep DF-set probe sizes to find the largest frame the path carries (`0` disables) |
| `-adaptive` | `true` | Adaptive RFC 6298 RTO |
| `-source` | `""` | Source label on every series, e.g. the local site (`sydney-dc`); defaults to hostname |
| `-metrics-user` | `""` | Basic auth username for `/metrics` (env `LINK_PING_METRICS_USER`) |
| `-metrics-pass` | `""` | Basic auth password for `/metrics` (env `LINK_PING_METRICS_PASS`) |
| `-metrics-tls-cert` | `""` | TLS certificate file for `/metrics` (requires `-metrics-tls-key`) |
| `-metrics-tls-key` | `""` | TLS private key file for `/metrics` (requires `-metrics-tls-cert`) |
| `-metrics-allow-insecure` | `false` | Allow Basic Auth without TLS; plaintext auth is otherwise rejected |
| `-metrics-gzip` | `false` | Gzip-compress `/metrics` when the scraper offers it |
| `-mem-scavenge` | `5m` | Force a heap scavenge at this interval so unused heap returns to the OS (`0` disables; `100ms` minimum) |
| `-json-logs` | `false` | Log in JSON format |
| `-log-file` | `""` | Append logs to this file too (required under the Windows service) |
| `-log-file-max-mb` | `10` | Max log size in MB before rotation (`0` disables) |
| `-log-file-max-backups` | `5` | Max rotated files to keep (`0` keeps all — pair with `-log-file-max-age`) |
| `-log-file-max-age` | `28` | Max days to keep rotated files |
| `-svc` | `""` | Windows service action: `install`, `uninstall`, `start`, `stop`, `run` |
| `-echo-secret` | `""` | HMAC probe secret (env `LINK_PING_ECHO_SECRET`); set on both ends; frame grows to 32 bytes |
| `-echo-secret-old` | `""` | Server: previous HMAC secret accepted during a rotation (env `LINK_PING_ECHO_SECRET_OLD`); error without `-echo-secret` |
| `-hmac-coverage` | `full-frame` | Client: bytes the HMAC tag covers — `full-frame` (header + `-payload`) or `header` (v0.7) |

More detail:

- `-mode` defaults to `server`, and a server only echoes: no target is loaded,
  no `link_up` series is exported and `/readyz` answers 200 regardless. An
  agent started with client-probing flags (`-target`, `-targets`, `-interval`,
  `-timeout`, …) and no `-mode` logs one warning naming the flags it dropped —
  a monitor that reads healthy while measuring nothing.
- `-allow-from-targets`: one shared targets file serves a whole mesh:
  adding or renumbering a site is a one-line edit picked up by reload. Every
  address must be an IP literal, because config load never resolves; combines
  with `-allow`.
- `-interval` / `-timeout`: below `1ms` is rejected, as is an effective
  timeout over 1000x the interval (that ratio is the in-flight window). With
  `-adaptive=false`, a timeout below `200ms` warns of spurious loss on
  moderate-RTT links.
- `-reconnect-interval`: below `-interval` is rejected; `0` falls back to 5m.
  Set `24h` to disable re-dialing.
- `-targets-reload-interval`: `0` disables; SIGHUP also reloads on Unix, and
  Windows services need this flag.
- `-mtu-sweep`: Linux; Windows for IPv4 on 2003+ and IPv6 on 2019+/Win10
  1703+. Unsupported socket options disable just the sweep, with one warning.
  Results: `link_path_mtu_bytes`, `/status path_mtu_bytes`.
- `-adaptive=false`: a link whose true RTT exceeds the fixed `-timeout` reads
  as 100% loss with no warning — pick a timeout above the expected RTT.
- `-metrics-user`: a username containing `:` is refused: Basic Auth splits at
  the first colon.
- `-metrics-pass`: prefer the environment variable, to keep the value out of
  `ps`.
- `-metrics-gzip`: off by default: promhttp pools one gzip writer per CPU
  holding ~0.7MB of flate state — up to ~0.7MB x `GOMAXPROCS`.
- `-mem-scavenge`: below `100ms` is refused (exit 1), because every tick is a
  stop-the-world `runtime.ReadMemStats` (plus a `debug.FreeOSMemory` once the
  releasable threshold is met) in a process whose job is measuring RTT. Also
  skipped unless at least 4MB of releasable heap is held
  (`HEAP_IDLE - HEAP_RELEASED`). Runtime tuning, including the 128MiB
  `GOMEMLIMIT` default, is in
  [operations and tuning](docs/operations.md#memory-and-runtime-tuning).
- `-log-file`: the agent enforces mode `0600` at startup, repairs wider modes
  and refuses symlinked paths, since logs carry peer IPs and topology. On
  Windows the same DACL applies: SYSTEM, Administrators and the service
  account only, protected from inheritance.
- `-hmac-coverage`: `full-frame` closes payload substitution riding a captured
  tag and needs `-payload > 0` to differ from `header`; `header` probes
  through a v0.7 echo server. The server accepts both whenever it has
  `-echo-secret`, so upgrading it to >= v0.8 clears the one broken pairing
  (v0.7 server + full-frame client). Invalid values are a startup error.

### Examples

Client:

```sh
./link_ping_prometheus -mode=client -target="192.0.2.10:4000" -metrics="127.0.0.1:2112"
```

Client, multiple targets:

```sh
./link_ping_prometheus -mode=client -targets=targets.json -metrics="127.0.0.1:2112"
```

Server:

```sh
./link_ping_prometheus -mode=server -listen=":4000" -allow=192.0.2.11 -metrics="127.0.0.1:2112"
```

Both:

```sh
./link_ping_prometheus -mode=both -targets=targets.json -allow=192.0.2.11 -metrics="127.0.0.1:2112"
```

### Targets file

A JSON array of `{"name": "...", "address": "host:port"}`, with optional
per-target `interval`/`timeout` overrides (duration strings; absent or `0`
uses the globals):

```json
[
  {"name": "site-a", "address": "192.0.2.10:4000"},
  {"name": "site-b", "address": "192.0.2.11:4000", "interval": "200ms", "timeout": "800ms"}
]
```

Max 1000 targets, max file size 1 MB. The
[targets file guide](docs/targets-file.md) covers the address syntax, hot
reload and the one-file-for-a-whole-mesh pattern.

## Metrics

`/metrics` (default port 2112) exposes the series below. Client-side series
carry `{source, target, address}`; server-side series carry `{source, client}`;
`link_metrics_auth_failures_total` has no labels and `link_ping_build_info`
uses `{version}`. Wrap raw counters in `rate()` over a window matching the
shortest outage you want to read as 100% loss.

| Metric | Type | Description |
| --- | --- | --- |
| `link_up` | Gauge | 1 while probes get echoes; 0 after 3 consecutive timeouts or when probing is impossible |
| `link_probes_sent_total` | Counter | UDP probes sent; down-link probes still count and time out |
| `link_probes_timed_out_total` | Counter | Probes with no echo within their RTO — true network loss |
| `link_probes_corrupted_total` | Counter | Echoed payload bytes altered in flight (`-payload` only) |
| `link_mtu_probes_sent_total` | Counter | DF-set probes sent by the MTU sweep, counted per attempt |
| `link_mtu_probes_lost_total` | Counter | DF-set MTU probes with no echo, per attempt: lost/sent stays a per-probe ratio |
| `link_path_mtu_bytes` | Gauge | Largest DF-set probe frame that round-trips, excluding IP/UDP overhead; 0 until first success |
| `link_probes_send_errors_total` | Counter | Probes that failed to send locally; never on the wire or in `sent` |
| `link_probes_throttled_total` | Counter | Probes skipped while the pending window was full — a probe-rate cut, not loss |
| `link_prober_internal_errors_total` | Counter | Prober-internal failures, by `reason`: `panic`, `reader_dead`, `dial_retry`, `stop_timeout` |
| `link_probes_inflight` | Gauge | Probes sent but still awaiting a response or timeout |
| `link_rtt_seconds` | Histogram | RTT histogram; bucket edges and native histograms below |
| `link_rtt_seconds_bucket/sum/count` | Histogram | Classic-bucket series; derive quantiles and means in PromQL |
| `link_rtt_jitter_seconds` | Gauge | Smoothed RTT jitter (RFC 3550 §6.4.1), computed in the exporter; reset on the first echo after a sequence gap |
| `link_rto_seconds` | Gauge | Applied adaptive RTO (RFC 6298), doubled on timeouts, floor `max(200ms, 2x SRTT)` |
| `link_rtt_srtt_seconds` | Gauge | Smoothed RTT estimate (RFC 6298 SRTT); 0 with adaptive mode off |
| `link_server_probes_received_total` | Counter | Valid probes received by the server, per remote client IP |
| `link_server_echo_errors_total` | Counter | Validated probes the server failed to echo (local UDP write error) |
| `link_server_probes_dropped_total` | Counter | Probes dropped by the server, by `reason` (see Notes) |
| `link_server_clock_skew_seconds` | Gauge | Last clock skew (server minus client timestamp) for HMAC probes; positive = client behind |
| `link_server_unauth_hmac_frames_total` | Counter | Bare 32-byte HMAC frames received by a server with no `-echo-secret` (see Notes) |
| `link_metrics_auth_failures_total` | Counter | Rejected Basic auth attempts on `/metrics` and `/status` |
| `link_ping_build_info` | Gauge | Build version, always 1 |

Percentiles and loss are not precomputed: `rate()` and `histogram_quantile()`
derive them over any window (1m, 1h, 24h). `link_rtt_seconds` uses
explicit buckets `{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 3.0}`
seconds plus native histograms (`NativeHistogramBucketFactor` 1.1), alongside
the library's `promhttp_metric_handler_requests_*` counters.

Notes:

- A full-size Ethernet path reads `link_path_mtu_bytes` 1424, or 1432 with
  `-echo-secret` (the header grows from 24 to 32 bytes).
- A probe is retired at the first tick after its RTO: with `-interval` <=
  `-timeout` an echo up to one interval late counts as latency, not loss.
- Samples above the 3s bucket edge land in `+Inf` whenever the applied RTO or
  `-timeout` exceeds 3s, or an echo runs up to one interval late. The 3s cap
  bounds backoff growth, never the floor and never the configured seed:
  `-timeout=10s` is honoured with `-adaptive` on (it raises the ceiling) as
  well as off.
- `link_mtu_probes_*` count per attempt (a failed size is retried once), so
  `sent` is a probe rate, not a rate of distinct sizes; never in the loss
  ratio or the balance.
- The balance holds: `link_probes_sent_total` = `link_rtt_seconds_count` +
  `link_probes_timed_out_total` + `link_probes_inflight`, plus
  `link_probes_corrupted_total` with `-payload`.
- `link_up` also reads 0 in the dial-retry loop and after 3 consecutive send
  failures; one lost probe never flaps it.
- `link_server_probes_received_total` includes MTU-sweep probes: subtract
  `rate(link_mtu_probes_sent_total)` before reading a mismatch as wire loss,
  and `rate(link_server_echo_errors_total)` before blaming the network.
- Alert on `link_mtu_probes_lost_total / link_mtu_probes_sent_total` (e.g.
  `> 0.2`), not on `> 0`: rising loss with healthy main probes is the PMTUD
  blackhole signature — works small, fails big.
- `link_server_probes_dropped_total` reasons: `allowlist`, `rate_ip`,
  `rate_global`, `size`, `magic`, `hmac`, `replay`, `dup`, `invalid_addr`,
  `client_overflow`. `hmac`/`replay` separate secret or NTP misconfiguration
  from true loss. Server caps: 2000 probes/s per client IP, 10000/s globally.
- CIDR-matched client series are TTL-evicted when idle and restart at 0, so
  `rate()` across the return sees a counter reset. `client_overflow` means
  more CIDR-allowlisted IPs than the 1024-series cap.
- `link_server_unauth_hmac_frames_total` counts only the bare 32-byte frame:
  a secret-less 24-byte header plus exactly 8 payload bytes has the same
  shape, while anything longer is byte-for-byte a legitimate `-payload` probe
  and is deliberately not counted. Such frames are echoed either way, so on a
  `-payload` deployment the counter (and `LinkMonitorReflectorUnauthenticated`)
  cannot see a half-configured pairing and the allowlist is the only reflector
  control — verify both ends by configuration, not by metrics.

## Prometheus and Grafana

Scrape each node's `/metrics`, locally or remotely with `-metrics-user` /
`-metrics-pass` plus TLS:

- [PromQL examples](docs/promql.md) — loss, latency, jitter, baseline shift, outages
- [Alert rules](docs/alerting.md) — `rules/link-monitor.yml`
- [Scraping](docs/scraping.md) — scrape config, Grafana Alloy, [dashboard](grafana-dashboard.json)

## Building

```sh
go build ./...          # Linux
./dev_build.sh          # Linux + Windows binaries into build/
go test -count=1 ./...  # integration tests run real UDP on 127.0.0.1
```

See [development](docs/development.md) for the test layout, CI checks and code
structure.

## License

[GPL-3.0](LICENSE)
