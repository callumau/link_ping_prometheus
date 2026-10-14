# Operations

## MTU discovery

**Why MTU discovery (`-mtu-sweep`) matters:** 24-byte probes prove a path *exists* — they cannot prove it *carries full-size traffic*. VPN tunnels, PPPoE/GRE/VXLAN overlays and broken PMTUD routinely pass small packets while black-holing full-size ones — the classic "monitor says healthy, users say broken" failure. The sweep DF-marks probes on a dedicated socket, binary-searches the largest frame that round-trips, and publishes it as `link_path_mtu_bytes`; a shrinking gauge (or rising `link_mtu_probes_lost_total` while `link_up` stays 1) is that failure's signature. A size with no echo is retried once before the search shrinks — a single dropped probe on a lossy path would otherwise converge far below the real MTU and make the gauge flap between sweeps — so both MTU counters advance per attempt and read as a probe rate, not one probe per distinct size tested. It needs no ICMP and no extra firewall rules, uses separate counters that never enter the loss ratio, and is on by default (1m; `0` disables). Alert on `link_path_mtu_bytes < max_over_time(link_path_mtu_bytes[24h])`, or
on MTU probe loss as a RATIO (`rate(link_mtu_probes_lost_total[10m]) /
rate(link_mtu_probes_sent_total[10m]) > 0.2`) — a bare `> 0` fires on a
single retried probe, which a normal 1%-loss path produces routinely. `link_up`
deliberately stays 1 through an MTU shrink (24-byte probes keep flowing), so
the gauge — not `link_up` — is the MTU-specific alarm.

## HTTP endpoints

Liveness endpoints `GET /healthz` and `GET /readyz` on the same metrics listener return `200 ok` (`text/plain`) for Kubernetes/container probes. They are deliberately unauthenticated — only `/metrics` and `/status` are gated — and are available over both HTTP and HTTPS. `/healthz` is always 200; `/readyz` returns `503` while a client-mode agent has no target with a working socket (server-only mode is always 200), so a rollout waits for a real link. `/metrics` itself serves at most 2 concurrent scrapes — a third concurrent request gets `503`, and responses are bounded by a 30s write timeout — so a scrape storm cannot multiply gather trees against `GOMEMLIMIT`.

`GET /status` on the same listener serves a JSON snapshot of live per-target probe state — `link_up`, in-flight probes, consecutive misses, the current consecutive send-failure streak (`send_failures`, reset on any successful write; not a cumulative count), RTO/SRTT, `jitter_seconds`, last sequence number, socket age, `path_mtu_bytes` (largest DF frame proven to round-trip; 0 = no successful sweep yet), `last_echo_age_seconds` (-1 until the first echo) and `straggler` (1 while that target's probe loop was replaced but failed to join within 5s and is still winding down — its last values are not live) — for debugging a flapping target without log access. It also returns a `process` object with Go runtime memory and GC stats — `heap_alloc_bytes`, `heap_sys_bytes`, `heap_idle_bytes`, `heap_released_bytes`, `stack_inuse_bytes`, `gc_sys_bytes`, `sys_bytes`, `gc_count` and `goroutines` — so heap growth is observable remotely without a debugger. Like `/metrics`, `/status` serves at most 2 concurrent requests — a third concurrent request gets `503` — because the snapshot copies and sorts the whole registry and the `process` object can trigger a stop-the-world `runtime.ReadMemStats`. Unlike the health endpoints it is auth-gated exactly like `/metrics` (open only when no metrics auth is configured). The `process` snapshot is re-read at most once per second (`runtime.ReadMemStats` stops the world), so a burst of requests cannot inject pauses into the probe loop that inflate its own RTT samples.

## Resource footprint

Resource footprint: metric handles are resolved once per target at startup (no per-probe label lookups), and the Go heap is soft-capped at 128MB (`GOMEMLIMIT` env overrides) so RSS stays flat on long runs. For >100 targets set `GOMEMLIMIT=256MiB` (or higher) as a system environment variable and restart the service.

## Memory and runtime tuning

`GOMEMLIMIT` keeps its 128MiB default when the env var is unset; `GOGC` is left at Go's own default (100). Both remain env-overridable. A binding `GOMEMLIMIT` does not reduce the footprint of an idle agent — the runtime only reacts as the heap approaches the limit — so treat it as a safety valve for large target counts, not a footprint knob.

Every `/metrics` scrape allocates (gather trees, text encoding, optional gzip) and ratchets Go's heap high-water mark upward; the runtime does not return it while the agent is otherwise idle because scavenging is allocation-rate driven. On Windows the visible number is commit/working set, so this ratchet shows up there as steady growth.

`-mem-scavenge` (default `5m`, `0` disables) forces a scavenge on that interval so the high-water mark goes back to the OS; it is skipped unless at least 4MB of *releasable* heap is held (`HEAP_IDLE - HEAP_RELEASED`), the figure the scavenge can actually return, not total process memory — an already-lean process pays nothing. `/status` exposes the same picture as its `process` object for observing it remotely.

`GOGC` is the other lever, and the right value depends on the scrape load (both measured on one target):

- A bursty load (800 scrapes back to back) ended at `heap_sys` 14.7MB / total 22.5MB by default, versus 6.8MB / 14.4MB with `GOGC=50`, for ~0.8ms extra CPU per scrape.
- A quiet agent (sparse scrapes) measured *worse* at `GOGC=50`: RSS 19.8MB vs 16.7MB, `gc_sys` 2.77MB vs 1.47MB, and ~5x the allocation churn, because it GCs a small heap more often.

So set `GOGC=50` for scrape-heavy deployments and leave it unset (or raise it) for a quiet one. `GOMAXPROCS=1` was the lowest-footprint configuration measured (RSS 14.6MB vs 16.7MB) at the cost of GC parallelism.

`-metrics-gzip` is off by default for the same reason: `promhttp` pools one gzip writer per CPU and each writer holds a `flate` compressor of roughly 0.7MB (`hashHead` 1<<17 + `hashPrev` 1<<15 plus a 32KB window), so compression can retain up to ~0.7MB x `GOMAXPROCS` of live heap across scrapes — more than the entire `/metrics` body of a small fleet. Measured with 400 plain versus 400 compressed scrapes on one target: live heap 1.24MB vs 3.98MB and `heap_sys` 10.8MB vs 14.7MB. Enable it (`-metrics-gzip=true`) when the response is large enough for the bandwidth saving to matter.
