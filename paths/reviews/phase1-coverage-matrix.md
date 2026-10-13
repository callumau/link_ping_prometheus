## Review — Phase-1 test ↔ finding coverage matrix (read-only lane)

Verified by grepping the real test suites (`internal/prober/*_test.go`, `logacl_windows_test.go`, `main_test.go`, `test/*_test.go`); every test named below exists at the cited file:line. Scope: (a) the 6 findings in `paths/reviews/release-races.md`, (b) the audit-round fixes `a3e8a57..222a8aa` as dispositioned in `paths/reviews/audit-fixes.md`. I did not modify any file.

### A. release-races.md findings

| Finding | Pinning test(s) | Grade | Testable headless | Sketch if missing |
|---|---|---|---|---|
| MED-1 `readEcho` ctx-skips unbounded by arm (mtu.go) — FIXED in commit fc724360 (ctx checkpoint on every received datagram, `internal/prober/mtu.go:186–190`) | `TestReadEchoCancellationBoundedByDatagramStream` — internal/prober/mtu_read_test.go:337 (far-future deadline, foreign-datagram stream, cancel → `context.Canceled` within 2s) | **DIRECT** | n/a (exists) | — |
| MED-2 exit accounting races live reader → echo charged as timeout (client.go:1318–1337) — FIXED (conn.Close first + bounded `readerDone` join ≤ `mtuReadArm` before drain) | No dedicated pin. Closest: `TestEchoLoop_ReaderDeathDrainsReceivedEcho` (internal/prober/client_recovery_test.go:350) pins drain-before-flush ordering, but its reader is already dead at exit — fix removal would NOT fail it; `TestGracefulShutdown_NoPhantomTimeouts` (test/client_test.go:595), `TestBalanceHoldsAcrossKeptSeriesRestart` (test/reload_test.go:243), `TestReconnect_KeepsProbingAndBalance` (test/client_test.go:803) exercise restart/shutdown accounting under `-race` only | **INDIRECT** | **YES** (deterministic, <1s sleep) | **Sketch:** real UDP echo server + scripted conn whose reader sleeps ~200ms between `Read` and pushing the echo into `respCh`; one probe in flight when ctx is cancelled; call `runEchoLoop` directly, let it return, assert `link_probes_timed_out_total` unchanged and rtt_count == 1. Post-fix the bounded join (500ms > 200ms delay) drains the echo as RTT; pre-fix the non-blocking drain charges it as loss. Un-tagged → runs on linux CI and windows-latest |
| LOW-3 dying loop's final `Update` clobbers `Straggler:true` (status.go:60–70 preserve logic) — FIXED | **None.** No test file references `TargetStatus.Straggler` (grep: zero hits); the two straggler tests (`TestRunClient_StragglerStillWantedIsRestarted` internal/prober/client_straggler_test.go:119, `TestRunClient_StragglerRemovedBeforeExitIsPurged`:214) assert only `statusHasName`, never the flag value | **NONE** | **YES** (pure registry test, <10ms) | **Sketch:** `reg.Update(TargetStatus{Name:"t"})` → `MarkStraggler("t", true)` → `reg.Update(TargetStatus{Name:"t"})` (no flag) → assert `Snapshot()[0].Straggler == true`; then `MarkStraggler("t", false)` → assert false (release path must still clear). Untagged → linux + windows-latest |
| LOW-4 `stragglerReLogInterval` claimed test-tunable but was a local — FIXED (promoted to package var, client.go:185) | **None.** The var is now reachable, but no test references it and no test asserts the 60s re-log (`grep "Probe targets stranded"` in `*_test.go`: zero hits) | **NONE** | **YES** (≤1s sleeps) | **Sketch:** `stragglerReLogInterval = 50ms`, `stragglerStopTimeout = 100ms`; `startStragglerFixture(delay=500ms)`; reload to mark the straggler; capture slog (test/helpers `logCapture` pattern); assert ≥2 `"Probe targets stranded"` Warn records within ~1s (mark-time Error log + ticker re-statements). Untagged → linux + windows-latest |
| LOW-5 sweep-socket write wedge (mtu.go:296 now sets a bounded `SetWriteDeadline` before each sweep `Write`) — FIXED | **None.** Test fixtures implement `SetWriteDeadline` as no-op stubs (mtu_read_test.go:37,330); no test asserts the deadline is set or that a blocking sweep `Write` is bounded | **NONE** | **YES** (white-box, <2s) | **Sketch** (package `prober`): fake conn whose `Write` blocks forever but records the last `SetWriteDeadline` value; run `sweepOnce` with `BaseTimeout=200ms`; assert `sweepOnce` returns within ~1s (bounded write → timeout) and `mtuLost` advanced. Untagged → linux + windows-latest |
| P2-6 dup-guard comment placement (server.go:771–785 vs 807–814) | Behavior already pinned: `TestEchoDupGuardRingEviction` (internal/prober/server_test.go:15), `TestEchoFrameKey` (:66), `TestServer_DupGuardBreaksEchoLoop` (test/server_test.go:1834), resolve-after-auth by `TestServer_UnauthenticatedSourceCannotSpendSeriesSlot` (test/server_test.go:1000) | **N/A** (comment prose; not test-pin-able) | no | — (review-only note; merging the two comment blocks is a doc edit, any code-order regression is caught by the DIRECT pins listed) |

### B. Audit-round fixes (a3e8a57..222a8aa, per audit-fixes.md)

**service-lifecycle lane**

| Finding | Pinning test(s) | Grade | Testable headless | Sketch if missing |
|---|---|---|---|---|
| HIGH-1 Stop returns nil on drain deadline (main.go:749–779) | `TestProgramStopTimeoutReportsCleanStop` — main_test.go:1426 (lowers `svcStopDeadline` var to 50ms) | **DIRECT** | n/a (exists) | — |
| HIGH-2 file-first MultiWriter | `TestHardenLogSink` (main_test.go:590) covers the file sink contract incl. Windows DACL branches; `TestCountedWriterFailureStreak` (:1453) covers the counter wrapper. No test pins the stdout-vs-file ORDER of the writer chain | **INDIRECT** | **YES** | **Sketch:** failing-stdout + healthy-file writer stack; write a log line; assert the file received it and the failure was counted (catches a revert to stdout-first). Untagged → linux + windows-latest |
| MED-3 DACL re-apply after rotation (logacl_windows.go:127–) | `TestReapplyLogDACL` (logacl_windows_test.go:91), `TestReapplyLogDACL_AfterRotation` (:122), `TestStartLogDACLRecheck_ReappliesAfterRotation` (:147, ticker at 20ms) | **DIRECT** | n/a (exists) — **windows-latest ONLY** (`//go:build windows`) | — |
| MED-4 README install-gap docs | — (prose) | **N/A** | no | — |
| MED-5 sink-failure visibility (logsink.go) | `TestCountedWriterFailureStreak` (main_test.go:1453) + `TestWatchLogSinkReportsToStderr` (:1498, os.Pipe stderr capture, 20ms watch interval) | **DIRECT** for countedWriter + foreground watcher; the service-handle/event-log arm runs with `svc=nil` and is **not** exercised (windows-only code path) | n/a (exists) | optional windows-latest-only test for the `svc != nil` event-log arm |
| LOW-8 /status 503 cap no longer hardcoded (main.go:861–872) | `TestStatusHandler_ConcurrencyCapReturns503` (main_test.go:1067) pins the cap behavior; the interpolated MESSAGE is not asserted (a re-hardcoded "2" would still pass) | **INDIRECT** | **YES** | **Sketch:** add one assertion to the existing test: the 503 body contains the interpolated `limit` value (catches reverting to a hardcoded literal). Untagged → both runners |

**probe-engine lane**

| Finding | Pinning test(s) | Grade | Testable headless | Sketch if missing |
|---|---|---|---|---|
| MED-1 respCh sized to adaptive window | `TestResponseBufferCapacity` — internal/prober/client_throttle_test.go:208 (static/adaptive/cap/floor table) | **DIRECT** | n/a (exists) | — |
| MED-2 probeTarget joins the sweep + sliced read arms (client.go:848–866) | Arms: DIRECT via `TestReadEchoCancellationBoundedByDatagramStream` (mtu_read_test.go:337). The `sweepDone` join itself: no test references it (grep: zero hits) — mtu tests cancel `RunClient` through it but nothing would fail if the join were removed | Join: **INDIRECT** | **YES** | **Sketch:** config with `MTUSweep` enabled, cancel `RunClient` mid-sweep, assert the RunClient goroutine joins within ~1.5s (join bound = `mtuReadArm` + socket close). Untagged → linux + windows-latest |
| MED-3 wedged straggler visible: /status `Straggler` field + 60s re-log | Straggler machinery DIRECT: the two `TestRunClient_Straggler*` tests. The field's /status observability and the re-log: **none** (see A rows 3–4) | field+relog: **NONE** | **YES** | see A rows 3–4 sketches |
| LOW-4 negative reload interval rejected (prober.go:198–205) | **None.** `TestConfigValidate*` tables (test/validation_test.go:118+, internal/prober/validation_test.go) have no `ReloadInterval` row (grep: zero hits in tests) | **NONE** | **YES** (pure) | **Sketch:** `Config{Targets:..., BaseInterval: 500ms, BaseTimeout: 1s, ReloadInterval: -1s}` → `Validate()` must error containing "reload interval". Untagged → linux + windows-latest |
| LOW-5 reader goroutine panic recovery (client.go:1059–1066) | **None.** No reader-panic test exists (grep: zero hits); the panic tests (`TestEchoLoop_PanicFlushCountsTimeouts` client_recovery_test.go:231, `TestEchoLoop_PanicFlushRestartNoDoubleCount` :288, `TestProbeTarget_PanicRestartCyclesKeepBalance` :793) cover only the echo-loop panic path | **NONE** | **YES** (<2s) | **Sketch:** conn whose `Read` panics once (then returns deadline-exceeded); run `runEchoLoop`; assert `link_prober_internal_errors_total{reason="panic"}` ≥1 and the loop exits via `errReaderDead` (readerDone closed), then re-dials. Untagged → linux + windows-latest |
| LOW-6 bounded `drainLive` (client.go:492–511) | Exercised on every `RunClient` cancel (all reload/client suites) and by `TestProgramStartStopBothMode` (main_test.go:938); the straggler arm of drainLive is only reached on shutdown-with-straggler, which no test does | **INDIRECT** | **YES** (straggler fixture + cancel mid-straggler, assert RunClient returns ≤ `stragglerStopTimeout`) | optional: `startStragglerFixture(600ms)`, mark straggler via reload, cancel, assert `RunClient` returns within ~1s. Untagged → both runners |

**windows-platform lane (installer .bat — no Go test harness exists)**

| Finding | Pinning test(s) | Grade | Testable headless | Sketch if missing |
|---|---|---|---|---|
| HIGH-1 cleanup_custom reachable; MED-1 sc.exe start check; MED-2 sidtype/icacls fatal; MED-3 uninstall exit codes; LOW-1 event-log orphan; LOW-2 bounded wait loops | **None** — no test executes the batch scripts | **NONE** | **NO** (needs a real Windows host with SCM/admin rights to install/uninstall a service; the CI windows-latest job runs `go test` only, never the .bat scripts) | — (recommend a manual post-release install/uninstall runbook step, or a PowerShell-based integration job if the team ever wants it automated; out of scope for Go unit tests) |
| MED-4 IPV6_DONTFRAG=14 confirmed | Comment-pin only (internal/prober/mtu_windows.go:20–25); no windows socket-option test exists (only `TestSetDontFragment_MarksV4Socket` for linux, mtu_linux_test.go:16) | **NONE** (behavior) | **NO** — a `setDontFragment` round-trip test is linux-impossible; it must live behind `//go:build windows` and would run on windows-latest only | **Sketch:** windows-tagged test: connected UDP socket → `setDontFragment` → `GetsockoptInt(IPPROTO_IP, ipDontFragment)` == 1 (v4); v6 branch mirrors it |
| LOW-3 AGENTS/README ladder docs | — | **N/A** | no | — |

**echo-server lane**

| Finding | Pinning test(s) | Grade | Testable headless | Sketch if missing |
|---|---|---|---|---|
| MED-1 dup-guard record-before-write, after resolution (server.go:767–814) | `TestServer_DynamicClientEviction` (test/server_test.go:1440), `TestServer_DupGuardBreaksEchoLoop` (:1834), `TestEchoDupGuardRingEviction` (internal/prober/server_test.go:15), `TestEchoFrameKey` (:66), resolve-after-auth via `TestServer_UnauthenticatedSourceCannotSpendSeriesSlot` (test/server_test.go:1000) | **DIRECT** | n/a (exists) — real UDP loopback, runs on linux + windows-latest | — |
| MED-2 README fixed-window wording | — | **N/A** (docs) | no | — |
| MED-3 replay-window edge both directions (skewReplayed) | `TestSkewReplayedBoundary` (internal/prober/server_test.go:100) + end-to-end `TestServer_ReplayWindowEdges` (test/server_test.go:654, ±4s margins vs 30s window) | **DIRECT** | n/a (exists) — both runners | — |
| LOW-1..5 cosmetics (2 fixed, 2 skipped) | — | **N/A** | no | — |

**resource-durability lane**

| Finding | Pinning test(s) | Grade | Testable headless | Sketch if missing |
|---|---|---|---|---|
| Zone trailing dot rejected (validZone) | `TestValidateTarget_IPishHosts` row "IPv6 zone with dangling trailing dot rejected" (internal/prober/validation_test.go:46); positive/negative zone rows in `TestValidateTarget_PortAndHostRules` (test/validation_test.go:60–94) | **DIRECT** | n/a (exists) — both runners | — |
| MTU-lost counts local writes (docs) | Help text updated (internal/prober/metrics.go:60) but **no test pins it** — only `LinkUp` Help is pinned (`TestLinkUpHelpPinsMissThreshold`, test/metrics_test.go:28) | **N/A** (prose) | optional: extend the Help-pin pattern to `MTUProbesLost` — trivial, both runners | — |
| heap ratchet / /status / MTU sockets / reload purge | — | **no issues found** in ledger; n/a | — | — |

### Summary

- **DIRECT pins missing (P2 gaps, all headless-testable, all untagged → run on BOTH linux CI and windows-latest):**
  1. `StatusRegistry.Update` preserving `Straggler:true` (finding 3) — pure unit test.
  2. `stragglerReLogInterval` 60s re-log (finding 4 / audit probe MED-3) — needs the new var, ≤1s sleeps.
  3. Bounded sweep `SetWriteDeadline` (finding 5) — white-box fake conn.
  4. Exit-accounting race vs live reader (finding 2 / commit fc724360) — deterministic scripted-reader pin; the only one of the four that is timing-coupled (join bound 500ms vs a 200ms reader delay).
  5. `Config.Validate` rejecting negative `ReloadInterval` (audit probe LOW-4) — one-line table row.
  6. Reader-panic recovery (audit probe LOW-5) — panic-once conn.
- **Windows-latest-only coverage:** the DACL re-apply tests (logacl_windows_test.go) and the winsock errno test (unreachable_windows_test.go) are the only windows-tagged pins; the installer .bat fixes have no automated coverage anywhere and are not headless-testable.
- Everything else in scope is DIRECT-pinned by existing tests.

**Merge verdict: OK with notes** — no merge blocker; the six missing pins above are the parent's implementation backlog for the follow-up coverage commit (I wrote nothing; per instructions the parent implements).