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

- `main.go` — flags, modes, metrics HTTP server (Basic auth + optional TLS), Windows service via `-svc`. Service hardening is pinned by `TestServiceConfigHardening` and must not be dropped: SCM OnFailure=restart (5s), DelayedAutoStart, Dependencies Tcpip+W32Time (clock sync is load-bearing for the HMAC replay window). Internal fatal errors under the service must exit non-zero (unclean) — never call `s.Stop()` on a run error, that reports a clean stop and SCM recovery will not fire. Install-time warnings: unset `-log-file` (stdout is discarded under the service → total log loss) and credential flags (never persisted into service config; delivered via env vars).
- `internal/prober/` — `client.go` (per-target UDP probe loop + reader goroutine; metric handles are resolved once per target into a `targetMetrics` struct — keep it that way, per-event `WithLabelValues` lookups are the hot path), `server.go` (single UDP read/echo loop + per-IP/global packet rate limits + fail-closed `-allow` client IP allowlist — `RunServer`/`ServePacketConn` reject any source not on the list; empty allowlist admits nothing and `RunServer` refuses to start), `adaptive.go` (RFC 6298 RTO), `metrics.go` (metric definitions), `validate.go`
- `test/` — integration tests (package `prober_test`) that spin real UDP echo servers on ephemeral ports; `udpEcho` helper in `client_test.go`, `startEchoServer` in `helpers_test.go`
- `installer/windows/` — enterprise service install/uninstall batch scripts (restart ladder, per-service SID, ACL'd log dir, credential env-var prompts). Keep in sync with the service hardening in `main.go` `serviceConfig()` and the README Windows checklist.
- Wire protocol: 24-byte UDP datagram — 8B magic `LNKPING\x00`, 8B little-endian seq, 8B little-endian unix-ns timestamp. When `-echo-secret` is set the frame grows to 32 bytes (trailing HMAC-SHA256 tag). Tests build/validate raw frames from this layout.
- Connection lifecycle is minimal by design: one dial per target with a 1s error-retry loop, plus a periodic re-dial (`ReconnectInterval`, default 5m) for DNS re-resolution. There is no reconnect/backoff storm logic — don't add any. Probes into a dead link time out naturally → loss reads ~100% during an outage with no fabricated counters.
- RTT is measured client-side only via monotonic clock subtraction (`sentTime` → arrival). The wire timestamp is an echo nonce/equality check, not a clock source — no NTP dependency, spoofed timestamps cannot poison RTT. Keep it that way.
- Jitter is RFC 3550-style smoothed |ΔRT| (÷16), updated only on consecutive-seq echoes. Sequence numbers are consumed only after a successful write, so local send failures no longer create gaps. Known ceiling: packet reordering within the pending window still resets the estimate to 0 (understates jitter on reorder-prone links) — fix only if reordering shows up in real deployments.
- Server replay guard: with `-echo-secret` set, frames whose timestamp skews more than `maxReplayWindow` (30s, server.go) from the server clock are dropped. Nodes must be roughly NTP-synchronized — document this in any deployment/user-facing doc you touch.
- Client failure thresholds live as named constants: `maxConsecutiveWriteFails` (client.go, 3 → link_up=0 at Error level). The reader goroutine returns after persistent `SetReadDeadline` failures rather than spinning. Keep these bounded-failure patterns if you add new loops.

## Metrics invariants (deliberate — do not break)

- Always balances: `link_probes_sent_total = link_rtt_seconds_count + link_probes_timed_out_total + link_probes_inflight`
- Every code path out of the `pending` map must touch exactly one of {rtt count, timed-out, inflight decrement}: match/echo, timeout sweep, write-error undo, **panic-recovery flush** (must ALSO count abandoned probes as timed out, not just drop inflight), reconnect flush. If you add an exit path, extend the balance-invariant test.
- Client loss is true network loss (UDP never retransmits). `link_server_probes_received_total` (server side) is a cross-check on `sent`, not the primary loss source.
- Adaptive RTO floor is `max(200ms, 2*SRTT)` with RFC 6298 doubling kept for recovery. A fixed 200ms floor caused spurious loss on ~185ms links.
- `link_up` = 1 while probes get echoes, 0 after 3 consecutive probes time out (`LinkUpMissThreshold`); a single lost probe must not flap it. `link_up` must also read 0 whenever probing is structurally impossible: inside the dial-retry loop and after N consecutive local send failures — a frozen `link_up=1` while nothing is being probed is the worst failure mode for a monitor.
- Removed (history): `link_flaps_total`, `link_connect_failures_total` were dropped in the TCP→UDP migration. Don't reintroduce connection-lifecycle metrics.

## Security invariants

- Server datagram handling order is deliberate: size check → allowlist (fail-closed) → rate limit → magic → HMAC. Cheap untrusted-source rejection MUST stay ahead of crypto work, or any internet host gets free HMAC-SHA256 CPU per flood packet (DoS on a latency-measuring box).
- HMAC (`-echo-secret`) authenticates the probe; the timestamp doubles as a replay nonce enforced by the ±30s freshness window above.
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
- Client metric label set is `{source, target, address}`; `ServerProbesReceived` uses `{source, client}`.
- Metric `Help` strings are user-facing docs — update README's metrics table when they change. Don't hardcode tunable values in Help text (e.g. the miss threshold) without a test pinning them together.
- README operational numbers must match code constants: rate-limit caps (`MaxPktsPerIP` = 2000/s per IP, `MaxPktsGlobal` = 10000/s), RTO bounds, bucket edges. Drift between docs and code has happened — check both sides when touching either.

## Tests

- Sleep-timed with tight tolerances; can be flaky under CI load (tests tolerate "cpu load?").
- `soak_test.go` is an opt-in long-run memory diagnostic — it skips unless `SOAK_SECONDS` or `SOAK_TARGETS` is set, so the default suite stays fast. Run `SOAK_SECONDS=600 go test -count=1 -run TestSoakMemory -v ./test/` for a soak. Heap must stay flat (+8MB ceiling over the run).
- Always pass `-count=1` to bypass the Go test cache.
- Helpers: `cfgWith(adaptive, interval, timeout, targets...)`; metric getters keyed by `testSource="test"`.
- Server rate-limit caps (`MaxPktsPerIP`, `MaxPktsGlobal`) are vars so tests can lower them — restore them in a defer after `ServePacketConn` returns.
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
