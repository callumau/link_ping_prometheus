# Development

## Build


```sh
go build -o ./build/link_ping_prometheus .
```

Cross-compile for Windows:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o build/link_ping_prometheus.exe .
```

## Test


```sh
go test -count=1 ./...          # full suite (~2 min; CI also runs it under -race)
go vet ./...
SOAK_SECONDS=600 go test -count=1 -timeout 15m -run TestSoakMemory -v ./test/   # opt-in memory soak (heap must stay flat, +8MB ceiling; -timeout required, the default 10m expires mid-soak)
```

**Test layout (Go ecosystem convention, as in prometheus/client_golang and windows_exporter):** unit tests live beside the code they exercise (`main_test.go` split by concern — `service_lifecycle_test.go`, `flags_test.go`, `http_endpoints_test.go`, `scavenger_test.go`, `rules_test.go`, `logsink_test.go`, `flags_test.go`; `internal/prober/*_test.go` beside the prober), and the **integration suite lives in `test/`** (`package prober_test`, one file per behavior — accuracy, jitter, reload, payload, HMAC coverage, MTU, server — with shared fixtures in `helpers_test.go` and the opt-in `soak_test.go`). Both suites run in CI; the Windows-only behavioral tests (winsock errno classification, DF socket options, log-DACL hardening) execute natively in the `test-windows` job.

Release binaries for Linux, macOS, Windows at [Latest Release](https://github.com/callumau/link_ping_prometheus/releases/latest).

## Code Structure


```text
main.go                     — CLI wrapper, flag parsing, service lifecycle
main_test.go                — lifecycle race, auth/TLS flag validation tests
main_metrics_test.go        — /metrics body decoding (gzip on/off)
internal/prober/
  prober.go                 — Config, protocol constants, HMAC helpers, pending-window cap
  adaptive.go               — RFC 6298 RTO estimation (AdaptiveStats)
  client.go                 — Target, LoadTargets, RunClient, UDP probe loop
  server.go                 — UDP echo responder, allowlist, rate limits, client series
  metrics.go                — Prometheus metric vars, InitMetrics, MetricsAuth
  status.go                 — /status registry (target snapshots + process memory)
  validate.go               — Target address validation (ValidateTarget)
  mtu.go                    — DF path-MTU sweep (shared search + state)
  mtu_linux.go              — IP_MTU_DISCOVER/IPV6_MTU_DISCOVER socket option
  mtu_windows.go            — Windows PMTUD with an IP_DONTFRAGMENT fallback ladder
  mtu_other.go              — sweep disabled on platforms without a DF option
  dscp_linux.go             — DSCP marking (IP_TOS/IPV6_TCLASS)
  dscp_other.go             — no-op elsewhere
  unreachable_other.go      — ICMP-derived read errnos (Unix)
  unreachable_windows.go    — ICMP-derived read errnos (winsock codes)
  adaptive_test.go          — RTO estimation, dynamic floor, backoff clamp
  client_recovery_test.go   — reader death, panic restart, write failure, dial retry
  client_retry_test.go      — dial failure retry, send-error accounting
  client_straggler_test.go  — reload stragglers: restart when wanted, purge when removed
  client_hmac_test.go       — client-side HMAC frames and the HMAC+payload offset
  hmac_coverage_test.go     — HMAC tag coverage: zero-payload equivalence, full-frame tag rules, flag parsing
  validation_test.go        — Config/target validation incl. the pending-window cap
  allowlist_test.go         — allowlist parser accepts and rejects
  unreachable_test.go       — peer-unreachable classification (Unix)
  unreachable_windows_test.go — same for winsock codes
  mtu_linux_test.go         — DF socket option applied to a v4 socket
  dscp_test.go              — DSCP socket option
  validate_dscp_test.go     — DSCP range validation
  bench_test.go             — resolve-once vs per-event label lookup, payload fill, allowlist
test/
  helpers_test.go           — Test utilities (metric inspectors, UDP echo server)
  adaptive_test.go          — AdaptiveStats logic and jitter adaptation
  validation_test.go        — LoadTargets, target parsing, Config validation
  server_test.go            — Server garbage handling, rate limits, allowlist, eviction
  client_test.go            — Robustness: loss, latency, corruption, spoofing, stalls, duplicates
  metrics_test.go           — Basic auth handler, metric seeding
  integration_test.go       — Multi-target, server dropout, stress (10 targets)
  accuracy_test.go          — Balance invariant, bucket placement, jitter ceiling, loss deadline
  precision_test.go         — Exact analytic assertions (RTO floor, jitter convergence)
  jitter_test.go            — RFC 3550 convergence, reset on gap, rebuild
  mtu_test.go               — Path-MTU sweep and its separate counter namespace
  hmac_coverage_test.go     — Server dual-accept rule + client wire bytes per coverage
  payload_test.go           — Corruption detection, counted apart from loss
  reload_test.go            — Hot reload: purge removed, keep changed, /status parity
  status_test.go            — Live /status snapshot contents, process object, cache
  timeout_override_test.go  — Per-target interval/timeout overrides
  soak_test.go              — Opt-in memory/goroutine soak (SOAK_SECONDS)
```

## Contributing


Bug reports and pull requests are welcome. Before opening a PR:

```sh
go build ./... && go vet ./... && go test -count=1 -race ./...
```

The integration tests run real UDP traffic on `127.0.0.1` and take a few
minutes. Keep changes one logical commit each (Conventional Commits style:
`feat:`, `fix:`, `docs:`). If a change touches metrics, flags, or constants,
update the README table in the same PR — docs and code drift together.
