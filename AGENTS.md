# AGENTS.md

Go module `tcp_ping_prometheus` — site-to-site link monitor: a UDP echo prober that exposes Prometheus metrics for latency, packet loss, and jitter. Runs in `server` (echo), `client` (probes), or `both` mode.

UDP is deliberate: no retransmission, so the loss ratio is true network loss (TCP probing hides loss as inflated RTT).

## Commands

- Build both platforms: `./dev_build.sh` (Linux + Windows into `build/`, gitignored)
- Full test: `go test -count=1 ./...` — real UDP on `127.0.0.1`, sleep-based, ~32s
- Focused: `go test -count=1 -run TestName ./test/`
- Verify before commit: `go build ./... && go vet ./... && go test -count=1 ./...`
- No linter configured; CI runs `go test -v ./...` + `go build -v ./...`

## Architecture

- `main.go` — flags, modes, metrics HTTP server (Basic auth + optional TLS), Windows service via `-svc`
- `internal/prober/` — `client.go` (per-target UDP probe loop + reader goroutine), `server.go` (single UDP read/echo loop + per-IP/global packet rate limits), `adaptive.go` (RFC 6298 RTO), `metrics.go` (metric definitions), `validate.go`
- `test/` — integration tests (package `prober_test`) that spin real UDP echo servers on ephemeral ports; `udpEcho` helper in `client_test.go`, `startEchoServer` in `helpers_test.go`
- Wire protocol: 24-byte UDP datagram — 8B magic `TCPPING\x00`, 8B little-endian seq, 8B little-endian unix-ns timestamp. Tests build/validate raw frames from this layout.
- No connection lifecycle: no dial/reconnect/backoff/flaps. Probes into a dead link time out naturally → loss reads ~100% during an outage with no fabricated counters.

## Metrics invariants (deliberate — do not break)

- Always balances: `link_probes_sent_total = link_rtt_seconds_count + link_probes_timed_out_total + link_probes_inflight`
- Client loss is true network loss (UDP never retransmits). `link_server_probes_received_total` (server side) is a cross-check on `sent`, not the primary loss source.
- Adaptive RTO floor is `max(200ms, 2*SRTT)` with RFC 6298 doubling kept for recovery. A fixed 200ms floor caused spurious loss on ~185ms links.
- `link_up` = 1 while probes get echoes, 0 after 3 consecutive probes time out (`LinkUpMissThreshold`); a single lost probe must not flap it.
- Removed (history): `link_flaps_total`, `link_connect_failures_total` were dropped in the TCP→UDP migration. Don't reintroduce connection-lifecycle metrics.

## Prometheus wiring

- `InitMetrics()` registers globals once via `registerOnce`; every test must call it before reading metric vecs.
- `SeedMetrics(source, targets)` pre-creates series so `/metrics` shows them before the first event.
- Client metric label set is `{source, target, address}`; `ServerProbesReceived` uses `{source, client}`.
- Metric `Help` strings are user-facing docs — update README's metrics table when they change.

## Tests

- Sleep-timed with tight tolerances; can be flaky under CI load (tests tolerate "cpu load?").
- Always pass `-count=1` to bypass the Go test cache.
- Helpers: `cfgWith(adaptive, interval, timeout, targets...)`; metric getters keyed by `testSource="test"`.
- Server rate-limit caps (`MaxPktsPerIP`, `MaxPktsGlobal`) are vars so tests can lower them — restore them in a defer after `ServePacketConn` returns.
- UDP test servers must close their `net.PacketConn` on ctx cancel, or `ServePacketConn`/read loops hang forever.

## Conventions

- Conventional Commits style in git log (`feat:`, `fix:`, `docs:`, etc.); one logical change per commit.
- `grafana-dashboard.json` is a tracked Grafana dashboard — edit carefully, it must stay valid JSON.
