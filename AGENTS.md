# AGENTS.md

Go module `link_ping_prometheus` — point-to-point link monitor: a UDP echo prober that exposes Prometheus metrics for latency, packet loss, and jitter. Runs in `server` (echo), `client` (probes), or `both` mode.

UDP is deliberate: no retransmission, so the loss ratio is true network loss (TCP probing hides loss as inflated RTT).

## Commands

- Build both platforms: `./dev_build.sh` (Linux + Windows into `build/`, gitignored)
- Full test: `go test -count=1 ./...` — real UDP on `127.0.0.1`, sleep-based, ~90–120s (2–3× under `-race`)
- Verify before commit: `go build ./... && go vet ./... && go test -count=1 -race ./...`
- Focused: `go test -count=1 -run TestName ./test/`
- Verify before commit: `go build ./... && go vet ./... && go test -count=1 ./...`
- No linter configured; CI runs `go vet ./...` + `go test -race -v ./...` + `go build -v ./...`

## Architecture

- `main.go` — flags, modes, metrics HTTP server (Basic auth + optional TLS), Windows service via `-svc`. Service hardening is pinned by `TestServiceConfigHardening` and must not be dropped: SCM OnFailure=restart (5s), DelayedAutoStart, Dependencies Tcpip+W32Time (clock sync is load-bearing for the HMAC replay window). Internal fatal errors under the service must exit non-zero (unclean) — never call `s.Stop()` on a run error, that reports a clean stop and SCM recovery will not fire. Install-time warnings: unset `-log-file` (stdout is discarded under the service → total log loss) and credential flags (never persisted into service config; delivered via env vars). `/metrics` serves at most 2 concurrent scrapes (excess → 503) under a 30s write timeout; `/readyz` returns 503 while a client-mode agent has no target with a working socket (server-only mode always 200); `-interval` below 1ms is rejected (the pending window grows as RTO/interval).
- Runtime tuning: `GOMEMLIMIT` defaults to 128MiB when unset; the agent deliberately does NOT override `GOGC` (measured: a lower GOGC shrinks the heap high-water mark under a bursty scrape load but costs more GC metadata and ~5x allocation churn at the sparse scrape rate a quiet agent actually sees) — both env vars always win. `/metrics` scrapes allocate and ratchet the Go heap high-water mark, which the runtime will not return while the agent is otherwise idle because scavenging is allocation-rate driven; `-mem-scavenge` (default 5m, `0` disables, skipped unless >=4MB of releasable heap — `HEAP_IDLE - HEAP_RELEASED` — is held, not total process memory) forces a scavenge so it goes back to the OS, and `/status` returns a `process` object (heap/stack/sys/GC bytes + `gc_count` + `goroutines`) alongside `targets`. `/metrics` compression is OFF by default (`-metrics-gzip`): promhttp pools one ~0.7MB flate compressor per P, so gzip can retain ~0.7MB x GOMAXPROCS of live heap - more than a small fleet's whole response; enable it for many targets.
- `internal/prober/` — `client.go` (per-target UDP probe loop + reader goroutine; metric handles are resolved once per target into a `targetMetrics` struct — keep it that way, per-event `WithLabelValues` lookups are the hot path; `RunClient` is a name-keyed supervisor so the targets file hot-reloads via SIGHUP / `-targets-reload-interval` / `Config.ReloadSignal` — reloads re-validate through `LoadTargets` and a broken file keeps the previous set running; a target REMOVED by a reload has its metric series deleted so Prometheus staleness applies — series in a vec are otherwise exported forever at their last value, i.e. a frozen `link_up=1`; a CHANGED target keeps them; a reload that parses to an empty array logs a warning that all probing stopped; a loop that fails to join within 5s is left stopped and its series purged once it does exit. A dead reader goroutine returns `errReaderDead` and the loop re-dials after a bounded 1s pause; the probe schedule is monotonic (every interval, not interval + loop work)), `server.go` (single UDP read/echo loop + per-IP/global packet rate limits + fail-closed `-allow` client IP allowlist — `RunServer`/`ServePacketConn` reject any source not on the list; empty allowlist admits nothing and `RunServer` refuses to start; the global rate charge runs pre-validation to bound HMAC work while the per-IP charge runs only post-authentication, so spoofed junk cannot spend a legit client's budget; CIDR-matched client handles AND their series are TTL-evicted under `MaxClientSeries` pressure via `DynClientTTL`, a var so tests can lower it; allowlist entries are `Unmap()`ed, so a `::ffff:10.0.0.1` entry matches an IPv4 client), `adaptive.go` (RFC 6298 RTO), `metrics.go` (metric definitions), `validate.go`
- `test/` — integration tests (package `prober_test`) that spin real UDP echo servers on ephemeral ports; `udpEcho` helper in `client_test.go`, `startEchoServer` in `helpers_test.go`
- `installer/windows/` — enterprise service install/uninstall batch scripts (restart ladder, per-service SID, ACL'd log dir, credential env-var prompts). Keep in sync with the service hardening in `main.go` `serviceConfig()` and the README Windows checklist.
- Wire protocol: 24-byte UDP datagram — 8B magic `LNKPING\x00`, 8B little-endian seq, 8B little-endian unix-ns timestamp. When `-echo-secret` is set the frame grows to 32 bytes (trailing HMAC-SHA256 tag). With `-payload` the client appends up to 1400 deterministic pattern bytes (header ≤ size ≤ header+1400 accepted server-side); the client validates the echoed pattern and counts mismatches as `link_probes_corrupted_total` — distinct from loss. The optional `-mtu-sweep` sends DF-set probes from a separate socket to binary-search the largest surviving frame (`link_path_mtu_bytes`); its counters are a separate namespace. Tests build/validate raw frames from this layout.
- Connection lifecycle is minimal by design: one dial per target with a 1s error-retry loop, plus a periodic re-dial (`ReconnectInterval`, default 5m) for DNS re-resolution. There is no reconnect/backoff storm logic — don't add any. Probes into a dead link time out naturally → loss reads ~100% during an outage with no fabricated counters.
- RTT is measured client-side only via monotonic clock subtraction (`sentTime` → arrival). The wire timestamp is an echo nonce/equality check, not a clock source — no NTP dependency, spoofed timestamps cannot poison RTT. Keep it that way.
- Jitter is RFC 3550-style smoothed |ΔRT| (÷16), updated only on consecutive-seq echoes. Sequence numbers are consumed only after a successful write, so local send failures no longer create gaps. Known ceiling: packet reordering within the pending window still resets the estimate to 0 (understates jitter on reorder-prone links) — fix only if reordering shows up in real deployments.
- Server replay guard: with `-echo-secret` set, frames whose timestamp skews more than `maxReplayWindow` (30s, server.go) from the server clock are dropped. Nodes must be roughly NTP-synchronized — document this in any deployment/user-facing doc you touch.
- Client failure thresholds live as named constants: `maxConsecutiveWriteFails` (client.go, 3 → link_up=0 at Error level). The reader goroutine returns after persistent `SetReadDeadline` failures rather than spinning. Keep these bounded-failure patterns if you add new loops.

## Metrics invariants (deliberate — do not break)

- Always balances: `link_probes_sent_total = link_rtt_seconds_count + link_probes_timed_out_total + link_probes_inflight` (plus `link_probes_corrupted_total` when `-payload` is enabled: a corrupted echo resolves the probe as corruption, not loss). The MTU-sweep counters (`link_mtu_probes_sent_total`/`link_mtu_probes_lost_total`) are deliberately a separate namespace and must never enter this balance — MTU probing must not pollute the loss ratio.
- Outside the balance by design, and never a loss denominator: `link_probes_send_errors_total`, `link_prober_internal_errors_total{reason}` (panic/reader_dead/dial_retry/stop_timeout — the prober's own health), `link_server_echo_errors_total` (the server received a valid probe but failed to write the echo), `link_metrics_auth_failures_total`.
- Every code path out of the `pending` map must touch exactly one of {rtt count, timed-out, inflight decrement}: match/echo, timeout sweep, write-error undo, **panic-recovery flush** (must ALSO count abandoned probes as timed out, not just drop inflight), reconnect flush. If you add an exit path, extend the balance-invariant test.
- Client loss is true network loss (UDP never retransmits). `link_server_probes_received_total` (server side) is a cross-check on `sent`, not the primary loss source; it also counts MTU-sweep probes (they carry the same header frame), so the documented cross-check subtracts `rate(link_mtu_probes_sent_total)` before calling a mismatch wire loss.
- Adaptive RTO floor is `max(200ms, 2*SRTT)` with RFC 6298 doubling kept for recovery. A fixed 200ms floor caused spurious loss on ~185ms links.
- `link_up` = 1 while probes get echoes, 0 after 3 consecutive probes time out (`LinkUpMissThreshold`); a single lost probe must not flap it. `link_up` must also read 0 whenever probing is structurally impossible: inside the dial-retry loop and after N consecutive local send failures — a frozen `link_up=1` while nothing is being probed is the worst failure mode for a monitor.
- Removed (history): `link_flaps_total`, `link_connect_failures_total` were dropped in the TCP→UDP migration. Don't reintroduce connection-lifecycle metrics.

## Security invariants

- Server datagram handling order is deliberate: size check → allowlist (fail-closed) → rate limit → magic → HMAC. Cheap untrusted-source rejection MUST stay ahead of crypto work, or any internet host gets free HMAC-SHA256 CPU per flood packet (DoS on a latency-measuring box).
- HMAC (`-echo-secret`) authenticates the probe; the timestamp doubles as a replay nonce enforced by the ±30s freshness window above. It must be set on BOTH ends: a server without it accepts the client's 32-byte HMAC frame as a bounded payload probe and echoes it, so a half-configured fleet reads healthy with no `hmac` drop reason and no reflector auth (the allowlist is then the only control). The server warns at startup when it is unset.
- Auth comparisons are hash-then-compare constant-time — don't replace with direct string/byte comparison.
- The metrics listener defaults to localhost; Basic auth + TLS are opt-in. Don't widen defaults.
- Security controls added to the wire protocol need table-driven tests (good frame accepted, bad tag dropped, wrong size dropped) — the SEC22 HMAC path shipped untested once already.

## Failure visibility

- Never convert a panic into a silent nil error. `ServePacketConn`'s recover must return an error so server mode exits non-zero and `both` mode tears down — a dead monitor that looks healthy (exit 0, stale metrics) is worse than a crash.
- Persistent local send failures are not "transient": after repeated write errors, log at Error and reflect reality in `link_up`. Debug-level logs are invisible at default verbosity.
- Reader/probe goroutines must have a bounded failure path — no bare `continue` loops on persistent per-iteration errors (busy-spin risk).

## Prometheus wiring

- `InitMetrics()` registers globals once via `registerOnce`; every test must call it before reading metric vecs.
- `SeedMetrics(source, targets)` pre-creates series so `/metrics` shows them before the first event.
- Client metric label set is `{source, target, address}`; `ServerProbesReceived` uses `{source, client}`. Diagnostic counters: `link_prober_internal_errors_total{source,target,address,reason}`, `link_server_echo_errors_total{source}`, `link_metrics_auth_failures_total` (no labels).
- Metric `Help` strings are user-facing docs — update README's metrics table when they change. Don't hardcode tunable values in Help text (e.g. the miss threshold) without a test pinning them together.
- README operational numbers must match code constants: rate-limit caps (`MaxPktsPerIP` = 2000/s per IP, `MaxPktsGlobal` = 10000/s), RTO bounds, bucket edges. Drift between docs and code has happened — check both sides when touching either. The README flags table must list every flag registered in `main.go` (`-echo-secret` drifted out once) and the bucket list must match `RTTBuckets` in metrics.go (2.5s/3s drift happened once).

## Tests

- Sleep-timed with tight tolerances; can be flaky under CI load (tests tolerate "cpu load?").
- `soak_test.go` is an opt-in long-run memory diagnostic — it skips unless `SOAK_SECONDS` or `SOAK_TARGETS` is set, so the default suite stays fast. Run `SOAK_SECONDS=600 go test -count=1 -run TestSoakMemory -v ./test/` for a soak. Heap must stay flat (+8MB ceiling over the run).
- Always pass `-count=1` to bypass the Go test cache.
- Helpers: `cfgWith(adaptive, interval, timeout, targets...)`; metric getters keyed by `testSource="test"`.
- Server rate-limit caps (`MaxPktsPerIP`, `MaxPktsGlobal`) are vars so tests can lower them — restore them in a defer after `ServePacketConn` returns. `DynClientTTL` and `MaxClientSeries` are exported vars for the same reason.
- Reading a purged series with `WithLabelValues` RE-CREATES it (at zero), so removed-target assertions must gather from the registry without creating anything (`test/reload_test.go` has the non-mutating helper). Assertions on exact counter equality across a teardown must give the echo server its own context: cancelling one shared context closes the server socket at the same instant the client writes its last datagram, which is a test race, not loss.
- UDP test servers must close their `net.PacketConn` on ctx cancel, or `ServePacketConn`/read loops hang forever.

## Conventions

- Conventional Commits style in git log (`feat:`, `fix:`, `docs:`, etc.); one logical change per commit.
- `grafana-dashboard.json` is a tracked Grafana dashboard — edit carefully, it must stay valid JSON.
- Dashboard ratio panels: numerator and denominator `rate()` windows MUST match (e.g. both `[5m]`). Mismatched windows produce wrong loss %/mean RTT across restarts and scrape gaps. Keep panel PromQL in sync with actual metric names/labels.

## Branching & workflow

- Start a new branch (e.g. `feat/...`, `fix/...`) for every coding task; never commit directly to main.
- Commit after each major logical change so every step is independently trackable and revertable — a history of one giant commit at the end defeats the point of branching.
- Never merge to main on your own: always ask the user first and wait for explicit approval before any merge.
- Work in parallel whenever possible: batch independent reads/commands into one turn, run independent tasks concurrently, and don't serialize work that has no dependency on each other.
