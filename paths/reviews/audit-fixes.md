# Audit round2-v0.8 — findings disposition ledger

All actionable findings from the 5 review lanes are fixed on this branch
(commits a3e8a57, 058c1de, 276e79c, 9619a7c, 8335c3a, 75e7add, 6669e66 + this).
Full verification: `go build ./...`, `go vet ./...` (linux + GOOS=windows),
`GOOS=windows go build ./...`, `go test -count=1 ./...`,
`go test -count=1 -race ./...` — all pass.

## service-lifecycle lane

| ID | Disposition | Where |
|---|---|---|
| HIGH-1 (SCM restarts operator stop) | FIXED — Stop returns nil on deadline, pinned by TestProgramStopTimeoutReportsCleanStop | main.go |
| HIGH-2 (MultiWriter stdout-first log loss) | FIXED — file-first in both sink modes | main.go |
| MED-3 (DACL regresses after rotation) | FIXED — 5-min idempotent re-apply (startLogDACLRecheck) | logacl_windows.go/other stub |
| MED-4 (manual install = 1 restart action, README over-promises) | FIXED (docs) — README now states the gap and which steps the wizard applies | README.md step 4 |
| MED-5 (sink failure invisible) | FIXED — countedWriter + event-log/stderr watcher every 30s | logsink.go |
| LOW-6 (no CheckPoint/WaitHint during stop drain) | SKIPPED — kardianos v1.2.4 exposes no checkpointing hook; upstream limitation, documented here |
| LOW-7 (system-shutdown drain vs WaitToKillServiceTimeout) | SKIPPED — same upstream constraint; the 20s cap is the best available bound |
| LOW-8 (/status 503 hardcodes cap) | FIXED — interpolated | main.go |
| LOW-9 (kardianos -svc=stop polling quirk) | SKIPPED — upstream bug, repo cannot fix |

## probe-engine lane

| ID | Disposition | Where |
|---|---|---|
| MED-1 (adaptive respCh under-sizing → fabricated loss) | FIXED — responseBufferCapacity pins adaptive to maxPendingWindow; pinned by TestResponseBufferCapacity | client.go |
| MED-2 (MTU sweep untracked; RTO-length wait) | FIXED — probeTarget joins the sweep; readEcho sliced into 500ms ctx-checked arms | client.go, mtu.go |
| MED-3 (wedged straggler silent) | FIXED — /status Straggler flag + 60s Warn re-log | status.go, client.go |
| LOW-4 (negative reload interval silently disables reload) | FIXED — rejected by Config.Validate | prober.go |
| LOW-5 (reader has no panic recovery) | FIXED — same contract as the echo loop | client.go |
| LOW-6 (shutdown join ignores stragglers/sweeps) | FIXED — bounded drainLive() | client.go |

## windows-platform lane

| ID | Disposition | Where |
|---|---|---|
| HIGH-1 (uninstaller custom-dir cleanup dead code) | FIXED — :cleanup_custom runs pre-deletion, reachable from both paths | uninstall-service.bat |
| MED-1 (sc.exe start unchecked) | FIXED — non-zero on failure + bounded RUNNING poll; wizard documents passwordless-accounts-only | install-service.bat |
| MED-2 (sidtype/icacls warning-only) | FIXED — both fatal | install-service.bat |
| MED-3 (uninstall exit codes unchecked → phantom service) | FIXED — binary only removed on successful uninstall | uninstall-service.bat |
| MED-4 (ipv6DontFrag=14 likely wrong) | INVALID — value CONFIRMED correct: Windows ws2ipdef.h defines IPV6_DONTFRAG = 14 (win32metadata, Winsock docs, Wine, ReactOS); citation pinned in comment | mtu_windows.go |
| LOW-1 (event-log source orphaned on sc-delete fallback) | FIXED | uninstall-service.bat |
| LOW-2 (unbounded stop-wait loops) | FIXED — 120s bound + taskkill hint | both scripts |
| LOW-3 (AGENTS CI / README ladder drift) | FIXED (docs) | AGENTS.md, README.md |

## echo-server lane

| ID | Disposition | Where |
|---|---|---|
| MED-1 (dup-guard flood slide) | FIXED — record before the echo write, after resolution (overflow frames not ring-poisoned; pinned by existing TestServer_DynamicClientEviction) | server.go |
| MED-2 (fixed-window 2× burst wording) | ALREADY COVERED — README documents the fixed window and 2× ceiling; no change needed | README.md |
| MED-3 (replay-window edge only pinned one direction) | FIXED — skewReplayed() + TestSkewReplayedBoundary pins strict >/<; exact ±30s edge is provably untestable over a real socket (processing-delay drift) | server.go |
| LOW-1..5 (cosmetics: lastSweep write sites, map capacity, pressure-sweep lastSweep, dynStop note, ctx-watcher goroutine) | LOW-2, LOW-3, LOW-5 FIXED (one-liners); LOW-1 and LOW-4 SKIPPED as refactor-only with no correctness delta — risk of touching pinned invariants outweighs cosmetic gain | server.go |

## resource-durability lane

| ID | Disposition | Where |
|---|---|---|
| LOW (zone trailing dot passes validation) | FIXED — validZone rejects a trailing dot; pinned by test | validate.go |
| LOW (mtu lost counts local write failures, undocumented) | FIXED (docs) — Help states the convention | metrics.go |
| heap ratchet / /status / MTU sockets / reload purge | NO ISSUES FOUND | — |
