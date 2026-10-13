## Review — Pre-release deep review lane: memory/CPU efficiency + code reduction (branch audit/round2-v0.8)

Scope: full read of `internal/prober/{client,server,mtu,status,metrics,adaptive,prober,validate}.go`, `main.go`, `logsink.go`; skimmed `bench_test.go`, `soak_test.go`, `hmac_coverage_test.go`, `mtu_read_test.go`. No source files modified. No P0/P1 issues found; all findings below are P2 (report-only / optional pre-release improvements), ranked by impact.

First, the things that are already right (verified, not assumed):
- Reader buffer reuse is correct: `buf := make([]byte, MaxDatagramSize)` and `payloadScratch` are allocated once per reader goroutine (client.go:1106-1112); the `response` struct is copied through the channel, not allocated per event.
- `pending` high-water shrink rule is present exactly as specified: realloc when drained and high-water >512 (client.go:1476-1481).
- Dup guard pruning is in lockstep: `record()` deletes the ring-evicted key from `seen` (server.go:173-186) — no unbounded `seen` growth.
- Dyn client map is TTL-swept both under traffic (gated in `resolve`, server.go:528-534) and by a dedicated ticker that runs with no traffic (server.go:555-577), and is capped by `MaxClientSeries`.
- `netip` keying of allowlist and rate limiter keeps the datagram path string-free (benchmarked in `BenchmarkAllowlistContains`); `echoFrameKey` FNV over 34 bytes is allocation-free.
- `/status` snapshot copy+sort is capped (`limitConcurrent(maxConcurrentScrapes)`, main.go) and `/readyz` uses the in-place `AnyReady` — no per-request copy on the unauthenticated endpoint.
- No dead code found: `targetByName`, `skewReplayed`, `flagDefaultInt`, `AnyReady`, `isIPishToken`, `benchSink`, `responseBufferCapacity` all have live call sites.
- The only O(n)-per-packet work is the allowlist prefix scan (≤256 entries, first-match-exit) — bounded and deliberate; the rate-limiter mutex is uncontended (single read-loop goroutine) so atomics would buy ~20ns/packet at real complexity cost. Not worth it.

### Findings

**P2-1 — HMAC hot path: `hmac.New` + `Sum(nil)` allocated per frame, on both client and server** (highest perf impact)
- Location: `internal/prober/prober.go:275-289` (`computeHMAC` — `hmac.New(sha256.New, …)` + `mac.Sum(nil)` per call), called per sent probe at `client.go:1560-1570` and `mtu.go:259-266`, and per received frame at `server.go:702-710` (`validHMACAny` → up to 2 constructions for rotation + full-frame fallback).
- Evidence: `crypto/hmac` keeps no reusable state; each call allocates the hmac struct (~200B incl. ipad/opad), the inner `sha256.digest`, and a 32B `Sum(nil)` slice — ~3 allocs / ~250B per frame, plus 2 sha256 block compressions for the pads that are identical every frame.
- Concrete change (tier 1, recommended now): hold one `hmac.Hash` per secret per goroutine (client: one field in `runEchoLoop` scope; server: one per secret in `ServePacketConn`), `Reset()` per frame, and `Sum` into a preallocated `[32]byte` via `mac.Sum(buf[:0])`. ~+15 LoC net ~0. Tags are byte-identical, and `hmac_coverage_test.go` pins header/full-frame tag equality, so regression risk is low.
- Tier 2 (the RFC 2104 precomputed-pads idea from the task): feasible without leaving `crypto/hmac` — snapshot the constructed mac once per secret via `encoding.BinaryMarshaler.MarshalBinary()` and `UnmarshalBinary()` it back per frame. Saves ~2 of 4 sha256 blocks (~0.5-0.7µs) and the remaining allocs. At the server's `MaxPktsGlobal` cap (10k/s) tier 1+2 removes ~2.5MB/s alloc churn and ~0.5-1% CPU; at a 1000-probe/s client it is ~0.1% CPU. Both call sites are single-goroutine, so the state reuse is safe.
- Verdict: tier 1 is a clear win (bytes + churn, trivial risk); tier 2 only if profiling shows HMAC >5% CPU at fleet scale — at 1000 probes/s it is not worth the hand-managed state.

**P2-2 — `respCh` costs ~48KB/target under adaptive; slim the response struct instead of shrinking it**
- Location: `client.go:1006-1010` (`type response{seq, ts uint64; recv time.Time; corrupted bool}` ≈ 48B), `client.go:1026` (`respCh := make(chan response, responseBufferCapacity(cfg))`), `responseBufferCapacity` returns `maxPendingWindow` (1000) whenever `-adaptive` is on — the default.
- Effect: 48KB allocated eagerly per probe loop; at the max supported fleet (1000 targets) that is ~48MB — over a third of the default 128MiB `GOMEMLIMIT` — re-made on every 5m reconnect. The *count* is load-bearing (a smaller channel parks the reader in the send-select, kernel-drops echoes, and fabricates loss — the comment at client.go:1012-1025 documents this; do not shrink it), but the *struct* is not: store `recv` as `int64` UnixNano instead of `time.Time` → 32B/entry → ~32MB, a 16MB saving at max fleet (32KB/target everywhere).
- Change: `recv int64` in the struct; `resp.recv = time.Now().UnixNano()`; RTT becomes `float64(resp.recv-sentTimeNS)/1e9` (store `pending` values as `int64` too). ~±10 LoC. Risk: low — the only consumer is `drainResponses`' RTT subtraction and `state.lastEcho` (convert back with `time.UnixNano` semantics).

**P2-3 — rate-limiter per-IP map bucket high-water retained by in-place `clear()`**
- Location: `server.go:196-204` (`resetLocked` uses `clear(r.perIP)`).
- Evidence: the map *contents* are bounded by the 1s window reset (verified: a spoof flood from rotating fake IPs inside an allowed CIDR — reachable only in secret-less mode, since `chargeIP` at server.go:732 runs post-authentication — creates at most `MaxPktsGlobal`=10k entries per window, then they are cleared). But Go's `clear` on a map keeps the bucket array sized to the high-water mark: one 1-second flood of ~10k distinct fake IPs permanently retains ~0.5-1MB of buckets for the server's lifetime.
- Change: in `resetLocked`, if `len(r.perIP) > 1024` reallocate (`r.perIP = make(map[netip.Addr]int, 64)`) instead of `clear`. ~4 LoC. Risk: trivial; window semantics unchanged.

**P2-4 — per-packet recomputation of constants (free wins)**
- `server.go:643-646`: `expectedSize` depends only on `echoSecret`, constant for the loop's lifetime — hoist above the `for`.
- `client.go:1121-1125`: same in the reader goroutine — hoist above the `for` (before `deadlineFails := 0`).
- Effect: negligible CPU (a branch or two per packet) but zero risk and zero LoC cost.

**P2-5 — code reduction: dial-failure `/status` update duplicates `emitTargetStatus` (−12 LoC)**
- Location: `client.go:858-871` builds a `TargetStatus` inline with fields omitted (LinkUp/SendFailures/Pending/SocketAge zero) — the same shape `emitTargetStatus` (client.go:636-668) produces for the panic path (`client.go:960` passes `0, 0`).
- Concrete change: replace the inline Update with `state.socketStart = time.Time{}` + `emitTargetStatus(m, state, stats, stats.CurrentRTO(), 0, 0)`. **The socketStart zeroing is required, not cosmetic**: `emitTargetStatus` derives `SocketAgeSeconds` from `state.socketStart`, which can hold a *previous* socket's dial time after a working socket dies; the current omitted-field form renders 0, which is what keeps `/readyz` not-ready during a prolonged dial outage (the reader-dead path at client.go:1437-1443 zeroes it for exactly this reason). With that one line, output is byte-identical to today's.
- Risk: low; behavior-identical with the zeroing. Verify with the existing dial-retry `/status` tests.

**P2-6 — code reduction: triplicated 1s pause block in `probeTarget` (−12 LoC net)**
- Location: `client.go:886-895` (dial fail), `936-945` (reader dead), `959-970` (panic restart) — identical `time.NewTimer(time.Second)` + `select {ctx.Done() with Stop/drain | t.C}`.
- Change: `func sleepCtx(ctx context.Context, d time.Duration) bool` helper (returns false on cancel); the two log-throttle blocks (`lastDialLog` pattern, 2 sites) could share a helper too, but the saving is marginal (~8 LoC) — optional.

**P2-7 — code reduction: timer stop/drain/reset pattern ×3 (−8 LoC)**
- Location: `mtu.go:46-49` and `mtu.go:70-73`, `client.go:1378-1382`. A `stopDrainReset(t *time.Timer, d time.Duration)` helper collapses all three. Risk: none.

**P2-8 — stray duplicated doc comment (−2 LoC)**
- `main.go:749-751`: the "Stop is called by the service framework…" comment sits above `svcStopDeadline` and is repeated verbatim above `func Stop` at main.go:755. Delete the first.
- Flag-only (per instructions, no rewrite): `runEchoLoop`'s ~50-line doc block (client.go:975-1030) and `ServePacketConn`'s doc (server.go:246-262) restate AGENTS.md invariants (balance, datagram ordering, dup-guard rationale) at length. They are accurate and load-bearing for review, but they duplicate the repo's pinned-invariant doc; a future pass could trim them to one-line pointers. Estimated −40 LoC if ever done; deliberately not proposed as a change now.

**P2-9 — items investigated and cleared (no action)**
- `fillPayload` per-byte xorshift over ≤1400B: ~1µs/probe, allocation-free, pinned by `BenchmarkFillPayload` — deliberate, leave it.
- `Snapshot()` copy+sort per `/status` request: capped at 2 concurrent; fine.
- `metricsHandler` one-line wrapper, `validHMACAny`/`validHMACFullFrameAny` symmetry: collapsing them adds indirection on the hot path for ~10 LoC — not worth it.
- No unbounded growth found anywhere else: `stragglers` map entries are deleted on release; `handles` (exact) is bounded by the ≤256-entry allowlist; `dyn` is TTL-capped; dup ring is fixed 8192.

### Totals
- Findings: 0 P0, 0 P1, 9 P2 (2 perf hot-path, 2 memory, 5 code-reduction/clarity).
- Net LoC if all reductions are taken: ~−36 (plus −40 optional comment trim flagged only).
- Memory at max fleet: ~16MB steady-state saving (P2-2) + ~1MB high-water (P2-3).
- Per-frame allocs removable: ~3 (~250B) client + up to ~6 server (rotation + full-frame fallback).

**Merge verdict: OK** — nothing here blocks release; P2-1 (tier 1), P2-2, and P2-3 are the ones I would take before v0.8 ships.

Tests a supervisor should run if any of the above are implemented: `go build ./... && go vet ./... && go test -count=1 -race ./...` (full suite, ~2-3× under `-race`), plus `go test -count=1 -run 'TestHMAC|TestMTU' ./internal/prober/` for the HMAC/MTU-pinned paths and `go test -bench . -run '^$' -benchmem ./internal/prober/` to confirm the alloc reductions.