# Operations

## MTU discovery

`-mtu-sweep` (default `1m`, `0` disables) proves a path carries full-size
traffic. A 24-byte probe proves only that the path exists: VPN tunnels,
PPPoE/GRE/VXLAN overlays and broken PMTUD pass small packets while black-holing
full-size ones — "monitor says healthy, users say broken".

The sweep DF-marks probes on a dedicated socket and binary-searches the largest
frame that round-trips, published as `link_path_mtu_bytes`.

- Watch for a shrinking gauge or a rising `link_mtu_probes_lost_total` while
  `link_up` stays 1.
- `link_up` stays 1 through an MTU shrink, so the gauge is the MTU alarm.
- A failed size is retried once before the search steps down, so one lost probe
  cannot converge below the real MTU.
- Both counters count attempts, not distinct sizes.
- No ICMP or firewall changes are needed; the counters never enter the loss
  ratio.
- Alert on `link_path_mtu_bytes < max_over_time(link_path_mtu_bytes[24h])`, or
  on `rate(link_mtu_probes_lost_total[10m]) /
  rate(link_mtu_probes_sent_total[10m]) > 0.2`. A bare `> 0` fires on a
  retried probe, routine on a 1%-loss path.

## HTTP endpoints

`GET /healthz` and `GET /readyz` are unauthenticated liveness endpoints on the
metrics listener; only `/metrics` and `/status` are gated. Both return `200 ok`
(`text/plain`) over HTTP and HTTPS.

- `/healthz` is always 200.
- `/readyz` returns `503` while a client-mode agent has no target with a
  working socket (server-only mode is always 200).

`/metrics` serves at most 2 concurrent scrapes (a third gets `503`) under a 30s
write timeout.

`/status` returns a JSON snapshot of live per-target probe state: `link_up`,
in-flight probes, consecutive misses, `send_failures` (current streak, reset on
any successful write), RTO/SRTT, `jitter_seconds`, last sequence number, socket
age, `path_mtu_bytes` (largest DF frame proven to round-trip; 0 = none yet),
`last_echo_age_seconds` (-1 until the first echo) and `straggler` (1 while that
target's probe loop was replaced but failed to join within 5s).

The snapshot also carries a `process` object (`heap_alloc_bytes`,
`heap_sys_bytes`, `heap_idle_bytes`, `heap_released_bytes`,
`stack_inuse_bytes`, `gc_sys_bytes`, `sys_bytes`, `gc_count`, `goroutines`).
Like `/metrics`, `/status` is auth-gated and serves at most 2 concurrent
requests (a third gets `503`): the snapshot copies and sorts the registry, and
`process` runs a stop-the-world `runtime.ReadMemStats`.

The snapshot is re-read at most once per second, so a burst cannot inject
pauses into the probe loop.

## Resource footprint

Metric handles resolve once per target at startup. Above 100 targets, set
`GOMEMLIMIT=256MiB` or higher as a system env var and restart.

## Memory and runtime tuning

`GOMEMLIMIT` defaults to 128MiB when unset and `GOGC` to Go's own default
(100); both are env-overridable. A binding `GOMEMLIMIT` does not shrink an idle
agent's footprint: it is a safety valve, not a footprint knob.

`/metrics` scrapes allocate (gather trees, text encoding, optional gzip) and
ratchet Go's heap high-water mark upward, which the runtime does not return
while the agent is idle.

`-mem-scavenge` (default `5m`, `0` disables) forces a scavenge so the
high-water mark returns to the OS. It is skipped unless at least 4MB of
*releasable* heap is held (`HEAP_IDLE - HEAP_RELEASED`) — not total process
memory — so an already-lean process pays nothing.

`GOGC` trades heap for CPU, and the right value depends on the scrape rate:

- Bursty scrape load: `GOGC=50` keeps the heap high-water mark lower, at the
  cost of extra CPU per scrape.
- Quiet agent: `GOGC=50` backfires — the runtime collects a small heap more
  often, burning CPU and GC metadata for no heap benefit.

Set `GOGC=50` only for scrape-heavy deployments; leave it unset (or raise it)
for a quiet one. `GOMAXPROCS=1` gives the lowest footprint, at the cost of GC
parallelism.

`-metrics-gzip` is off by default: `promhttp` pools one gzip writer per CPU,
each holding a ~0.7MB `flate` compressor, so compression can retain ~0.7MB x
`GOMAXPROCS` of live heap. Enable it (`-metrics-gzip=true`) for large
responses.
