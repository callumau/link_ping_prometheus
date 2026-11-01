# Long-term cross-platform test

The in-process soak (`SOAK_SECONDS`, see [development](development.md)) proves
the client loop does not leak in a single Go process. It does not exercise the
things that only break over days on a real fleet: the SCM/systemd service
lifecycle, log rotation, the Windows DACL recheck, clock drift against the
replay window, a real WAN path between two operating systems, and
scrape-driven heap growth.

This page is the runbook for the **two-node long-term test**: one Linux host and
one Windows host running the released binary in `-mode=both`, measuring each
other, left running for several days.

> Host identities are placeholders here on purpose. Do not put real site names
> or peer addresses in tracked files — that is exactly how the live
> `targets.json` ended up in published git history.

## Topology

The deployed test is **one-directional and cross-platform**: the Linux host is
the reflector, the Windows host is the prober. That is the shape the mesh
deployments use most often (one shared echo server per site, N clients), and it
puts the Windows client code — clock, MTU sweep, targets file, log/DACL — under
a real WAN path.

```text
   win-site (Windows, -mode=client)  ── UDP 4000 probes ──▶  linux-site (Linux, -mode=server)
        └──────────── TCP 2112 /metrics, /status ────────────────┘
```

| Node | Mode | Why |
|---|---|---|
| `linux-site` | `-mode=server` | exercises the echo loop, allowlist, rate budgets and metric cardinality under continuous load |
| `win-site` | `-mode=client` | exercises the probe loop, adaptive RTO, MTU sweep, targets file and the SCM service for days |

If you also want both endpoints' *client* code under soak (and the mixed-platform
echo path in both directions), run `-mode=both` on both hosts instead. That
doubles the probe load per host and adds the Windows echo loop; the daily checks
below are unchanged.

## Setup

Use the released binaries of the **same version** on both hosts and record it
(`link_ping_build_info`); a version skew invalidates the comparison.

**`targets.json` on the Windows prober** (one entry: the reflector). Keep it
0644 root-owned (POSIX) or admin-owned with an inherited-only DACL on Windows;
the agent refuses symlinks and group/world-writable files on POSIX and checks
the owner on both.

```json
[{ "name": "peer", "address": "203.0.113.10:4000" }]
```

**Linux reflector:** install from [linux-systemd](linux-systemd.md) with

```text
OPTIONS="-mode=server -listen=:4000 -allow=203.0.113.20 -metrics=127.0.0.1:2112"
LINK_PING_ECHO_SECRET=<32+ random bytes>   # 0600 env file
```

**Windows prober:** install from [windows-service](windows-service.md) with

```text
-svc=install -mode=client -target=203.0.113.10:4000 -metrics=127.0.0.1:2112 -log-file=C:\ProgramData\link_ping_prometheus\logs\service.log
LINK_PING_ECHO_SECRET=<same secret>        # SCM Environment value, key ACL'd
```

Use `-targets` + `-targets-reload-interval` instead of `-target` when the prober
also needs hot reload; a Windows service has no SIGHUP, so without the interval
the file is read once at start.

Checklist before starting the clock:

- [ ] `-echo-secret` set on **both** ends (a one-sided secret reads healthy with
      no `hmac` drop reason — see [security](security.md)).
- [ ] NTP/`W32Time` healthy on both; the replay window is ±30 s.
- [ ] `-allow` on each host lists the peer's egress address exactly, or a
      narrow prefix. Wide prefixes without a secret are warned at startup.
- [ ] If the prober uses `-targets`, `-targets-reload-interval` is non-zero on
      Windows (no SIGHUP under the SCM).
- [ ] Prometheus scrapes both `/metrics` (or a cron `curl` into a file, below).
- [ ] Both clocks and `TZ` recorded; logs are UTC.

## Daily check (5 minutes)

Run on each node, or paste the output back for analysis. The point is to compare
**today** with **T+10 minutes**, not with zero: the first sample still includes
startup allocation.

### Linux

```sh
curl -fsS http://127.0.0.1:2112/status | jq '{targets, process}'
curl -fsS http://127.0.0.1:2112/metrics | grep -E '^(link_up|link_probes_sent_total|link_probes_timed_out_total|link_probes_send_errors_total|link_probes_throttled_total|link_probes_corrupted_total|link_prober_internal_errors_total|link_server_probes_dropped_total|link_server_echo_errors_total|link_server_clock_skew_seconds|link_path_mtu_bytes)'
ps -o pid,etime,rss,vsz,cmd -p "$(systemctl show -p MainPID --value link_ping_prometheus)"
ls -l /var/log/link_ping_prometheus/ | tail -5
```

### Windows (elevated PowerShell)

```powershell
Invoke-RestMethod http://127.0.0.1:2112/status | ConvertTo-Json -Depth 4
(Invoke-WebRequest http://127.0.0.1:2112/metrics).Content -split "`n" |
  Select-String '^(link_up|link_probes_sent_total|link_probes_timed_out_total|link_probes_send_errors_total|link_probes_throttled_total|link_probes_corrupted_total|link_prober_internal_errors_total|link_server_probes_dropped_total|link_server_echo_errors_total|link_server_clock_skew_seconds|link_path_mtu_bytes)'
Get-Process link_ping_prometheus | Select-Object Id, StartTime, WorkingSet64, PrivateMemorySize64
Get-ChildItem C:\ProgramData\link_ping_prometheus\logs | Sort-Object LastWriteTime | Select-Object -Last 5
sc.exe query link_ping_prometheus
```

### What to record

| Signal | Where | Healthy over days |
|---|---|---|
| `process.heap_alloc_bytes` | `/status` | flat (±8 MB of the T+10m sample) |
| `process.heap_idle_bytes - heap_released_bytes` | `/status` | small and not climbing; `-mem-scavenge` should return it |
| `process.goroutines` | `/status` | flat (2 per target + server loops + scrape handlers) |
| `process.gc_count` | `/status` | rising steadily is normal; a jump in growth rate is not |
| RSS / private bytes | OS | flat; Windows commit is the one that grows if scavenging fails |
| `link_up` | metrics | 1 on both targets |
| loss | `rate(link_probes_timed_out_total)/rate(link_probes_sent_total)` | baseline +jitter, not climbing |
| `link_probes_send_errors_total` | metrics | 0 (local NIC/socket problem, not loss) |
| `link_probes_throttled_total` | metrics | 0 (otherwise the adaptive RTO outgrew the pending window) |
| `link_probes_corrupted_total` | metrics | 0 (data-path corruption, distinct from loss) |
| `link_prober_internal_errors_total` | metrics | 0 (panic/reader_dead/dial_retry/stop_timeout) |
| `link_server_probes_dropped_total{reason}` | metrics | no `rate_*`, `hmac`, `replay`, `client_overflow` |
| `link_server_echo_errors_total` | metrics | 0 (agent-side write failures) |
| `link_server_clock_skew_seconds` | metrics | within a few ms; a drift means NTP is failing |
| log size / rotation | OS | bounded by `-log-file-max-*`; no write-failure warnings |
| service restarts | `sc.exe query` / `systemctl show -p NRestarts` | unchanged |

### Interpreting a loss reading

A loss increase is not automatically the network. Check the drop reasons first:

| Symptom | Likely cause |
|---|---|
| `dropped_total{reason="rate_ip"}` rising on the reflector | probe rate above 2000/s per IP (targets × interval), or another monitor sharing the IP |
| `reason="rate_global"` | >10 000/s at that reflector |
| `reason="hmac"` or `"replay"` | secret mismatch, or clock drift beyond ±30 s |
| `reason="client_overflow"` | more CIDR-allowlisted clients than `MaxClientSeries` |
| `link_probes_send_errors_total` rising | local socket/NIC, not the path |
| `link_server_echo_errors_total` rising | reflector could not write the echo |
| loss with none of the above | true network loss |

## After the run

Stop both services normally (`systemctl stop`, `sc.exe stop` — never kill the
SCM service, it restarts on failure) and capture a final snapshot. Then compare
the first post-startup snapshot with the last one:

- heap and goroutines flat ⇒ no leak in the client loop, server loop,
  scrape path, log rotation or DACL recheck over N days;
- no `replay` drift ⇒ both clocks held through NTP;
- log rotation produced the expected files and the live file stayed 0600
  (POSIX) / SYSTEM+Administrators (Windows);
- `/readyz` stayed 200 and the service never restarted.

Record the interval, versions, and the before/after numbers in the PR or issue
that requested the run, so the next comparison has a baseline.
