## Review — Windows test coverage inventory (read-only, branch `audit/round2-v0.8`)

### 1. Tests that execute ONLY on windows-latest (never on linux)

**Natively windows-compiled test files (excluded from the linux build by `//go:build windows`):**

1. **`TestIsPeerUnreachable_WindowsErrnos`** — `internal/prober/unreachable_windows_test.go:15`. Pins the winsock errno classification in `peerUnreachableErrnos` (`unreachable_windows.go:26–34`): WSAECONNRESET/REFUSED/HOSTUNREACH/NETUNREACH/NETRESET are peer failures (reader must survive), wrapped winsock errnos still classify, and the portable `syscall.ECONNRESET`, `os.ErrDeadlineExceeded`, and generic errors are local failures. This is the exact cross-platform bug class AGENTS.md warns about (portable constants compile everywhere, never match on Windows).

2. **`TestHardenLogSink` Windows branches** — `main_test.go:596–602, 630–636, 649–666`. Runtime-gated (`runtime.GOOS == "windows"`), so on ubuntu these bodies take the POSIX perm-bit path and return; the DACL assertions run only on windows-latest:
   - "creates missing file at 0600" → asserts the created file's DACL is the restricted protected set (`verifyLogDACLRestricted`), not the parent's inherited grant.
   - "repairs pre-existing wide mode" → asserts the repair on Windows is a DACL restriction, plus content preservation.
   - "keeps a compliant file untouched" → pins `restrictLogDACL` idempotence (second run reports `repaired=false`, DACL still restricted).

   Supporting helper `verifyLogDACLRestricted` lives in `logacl_windows_test.go:32` (`//go:build windows`) — it contains **no Test functions**; it exists only to serve the runtime-gated call sites, with a no-op stub in `logacl_other_test.go` for `!windows` so the call sites compile.

**Runtime-divergent behavior executed natively but without windows-exclusive assertions** (worth stating so the inventory is honest): `test/mtu_test.go` and `internal/prober/mtu_read_test.go` have **no build tags**, so the MTU-sweep integration tests *do* execute `setDontFragment`'s IPv4 branch (`mtu_windows.go:59–64`, `IP_MTU_DISCOVER` → `IP_DONTFRAGMENT` fallback) against real loopback on windows-latest — code that is never executed on ubuntu (`GOOS=windows vet/build` only cross-compiles). However, no windows test *asserts* the socket option via getsockopt; the only getsockopt assertion is `mtu_linux_test.go:16` (`//go:build linux`). `TestServiceConfigHardening` (`main_test.go:102`) and the rest of `test/` run on both platforms (no GOOS gates exist in `test/` at all).

### 2. Windows-tagged files included in the windows job?

**Confirmed.** `test-windows` runs `go test -count=1 -race -timeout 30m -v ./...` from the repo root (ci.yml, test-windows job), which covers all three packages: `.`, `internal/prober`, `test`. Both windows-tagged test files are therefore included:
- `logacl_windows_test.go` (package `main`) — included (helpers only; exercised via `TestHardenLogSink`).
- `internal/prober/unreachable_windows_test.go` — included and executed.

Note: `mtu_windows.go` has **no** `mtu_windows_test.go` — its coverage is indirect only (see G4).

### 3. Coverage gaps — Windows-only behaviors with NO test on windows-latest

| # | Gap | Location | Headless w/o admin? |
|---|-----|----------|---------------------|
| G1 | `reapplyLogDACL` — **zero tests** (grep over all test files: no reference) | `logacl_windows.go:29–49` | ✅ Yes |
| G2 | `startLogDACLRecheck` ticker goroutine — **zero tests**; interval is a `const` 5m so it can't be timed in a test as-is | `logacl_windows.go:15, 54–71`, wired at `main.go:1004` | ✅ Yes (needs const→var) |
| G3 | Rotated-file DACL regression scenario — the exact bug the fix targets (lumberjack rename + fresh file inheriting wide dir DACL) has no test | `logacl_windows.go:20–27` comment; lumberjack v2.2.1 in go.mod | ✅ Yes |
| G4 | `setDontFragment` **IPv6 branch** (`IPV6_MTU_DISCOVER`/`IPV6_DONTFRAG`, `mtu_windows.go:65–72`) and the non-`SyscallConn`/non-UDPAddr guards (`mtu_windows.go:53–60`) — never executed on Windows; all test targets are `127.0.0.1`, IPv6 appears only in syntax validation (`test/validation_test.go:63–94`) | `mtu_windows.go` | ✅ Yes |
| G5 | DSCP on Windows (`dscp_other.go:13` — must return error; caller warns once and continues, `client.go:905–909`, `mtu.go:68–72`) — `dscp_test.go` is `//go:build linux`; no test sets `DSCP>0` on the client outside the pure-config range test (`validate_dscp_test.go`) | `dscp_other.go`, `client.go:905` | ✅ Yes |
| G6 | Installer `.bat` flows (delayed-expansion exclusion, `INSTALL_ARGS` quoting, trailing-backslash strip, restart ladder, log-dir grant) | `installer/windows/` | ❌ Manual-only (see note) |
| G7 | `restrictLogDACL` fail-closed on WRITE_DAC denial (`logacl_windows.go:118–127`) — requires simulating loss of ownership/WRITE_DAC, not reasonably testable headlessly | — | ❌ Manual-only |

The idempotence of `restrictLogDACL` itself **is** covered on Windows (TestHardenLogSink "keeps a compliant file untouched"), and `TestHardenLogSink`'s "refuses symlink" subtest runs on Windows but `Skipf`s if symlink creation is denied — acceptable.

**Test sketches** (all package `main` or `prober`, tagged `//go:build windows`, using `t.TempDir()` — the test process owns the file, so the owner's implicit WRITE_DAC makes `SetNamedSecurityInfo` succeed without elevation):

- **G1** — `TestReapplyLogDACL`: (a) seed file 0600, call `reapplyLogDACL(path)`, `verifyLogDACLRestricted`; (b) widen first: `windows.SetNamedSecurityInfo` with SDDL `D:P(A;OICI;FA;;;WD)` (or simply skip pre-hardening: a fresh `os.Create` file inherits TempDir's DACL, which is not the restricted set) → `reapplyLogDACL` must restore the restricted set and the second call must not error (idempotent); (c) nonexistent path → returns nil (mid-rotation gap, `logacl_windows.go:34–36`); (d) empty path → nil no-op.
- **G2** — change `logDACLRecheckInterval` from `const` to `var` (precedent: `DynClientTTL`, `stragglerStopTimeout`); test lowers it to ~20ms via defer-restore, seeds a wide file, calls `startLogDACLRecheck(ctx, path)`, polls until `verifyLogDACLRestricted` passes, cancels ctx and asserts the goroutine exits (observe via a probe file or simply bounded polling then cancel).
- **G3** — `TestLogDACL_SurvivesRotation`: `hardenLogSink(path)` → rename `path` to `path.1` (simulating lumberjack's rename) → `os.OpenFile(path, O_CREATE, 0o600)` — fresh live file now carries the *directory's* DACL, i.e. the regression → `reapplyLogDACL(path)` → assert `verifyLogDACLRestricted(path)` **and** that the renamed `path.1` still holds the restricted set (no accidental re-pointing). This is the scenario the MED-3 fix (audit-fixes.md) shipped for; it currently has zero execution coverage.
- **G4** — `TestSetDontFragment_Windows`: start a UDP echo server on `[::1]:0` (windows-latest has IPv6 loopback), dial it, `setDontFragment(conn)` must return nil; optionally `rc.Control` + `windows.GetsockoptInt(IPPROTO_IPV6, IPV6_MTU_DISCOVER)` == `IP_PMTUDISC_DO` to pin the modern path was taken (runner is Win10 1703+/Server 2019+, so the fallback path stays untested — acceptable, document). Second subtest: `setDontFragment(scriptedReadConn{})` (already in-package, `mtu_read_test.go:18`) must return a bounded error, not panic; third: a conn whose `RemoteAddr()` is not `*net.UDPAddr`.
- **G5** — `TestSetDSCP_WindowsUnsupported` in package `prober`: `setDSCP(conn, 46, addr)` returns an error; integration half in `test/`: run the client with `DSCP: 46` against `udpEcho` and assert `ProbesSent` advances — pins "probes continue unmarked" (the warn-and-continue at `client.go:906–909`), i.e. a regression that aborts dialing on the DSCP error fails immediately.

**G6 note (manual-only):** the .bat invariants cannot be meaningfully executed headlessly in CI — `-svc=install` mutates SCM state, prompts for credentials, and needs elevation. Recommend keeping them as documented manual checklist items (installer/windows/README.md), with the caveat that the three pinned invariants (no delayed expansion, per-arg quoting, backslash strip) are exactly the ones that regress silently; if a future lane wants automation, a `cmd /c` smoke that renders `INSTALL_ARGS` and asserts the argv split (without installing) is the smallest testable slice.

### 4. Sleep-timed suite under `-race` vs the 30m `-timeout`

Rough check: **OK today, with moderate headroom.** Evidence:
- The suite is ~90–120s locally, 2–3× under `-race` (AGENTS.md Commands), and the CI comment in ci.yml (test-windows) states "can take 10–20 min here" on the slower windows runners — already accounting for `-race`.
- 30m `go test -timeout` vs 45m job `timeout-minutes` → the go timeout fires first (correct ordering), leaving ~1.5–3× headroom over the observed 10–20 min.
- `soak_test.go` skips by default (`SOAK_SECONDS`/`SOAK_TARGETS` unset) so it contributes nothing.
- Risk direction: any new windows-only tests must not sleep at real intervals — in particular G2's sketch is only viable if `logDACLRecheckInterval` becomes a var and the test lowers it; a test that waits out the real 5m tick would push the suite toward the timeout. The existing `skipIfRTTNearTimeout` flake guards absorb runner noise but do not bound total wall time.

### Verdict

**OK with notes.** No P0 blockers for a release audit: the windows job does compile and execute the existing windows-tagged tests, and the shippable-behavior pins (winsock classification, log-DACL hardening, idempotence) are present. The inventory's material gaps are the *new* DACL re-apply path (`reapplyLogDACL`/`startLogDACLRecheck`, G1–G3 — shipped with zero tests, including the exact rotation-regression scenario it was built to close) and the never-executed IPv6 DF branch (G4). All four are headlessly testable on windows-latest without admin; recommend the G2 const→var change as the enabler. G6/G7 stay manual.

```json
{
  "review_target": "Windows test coverage inventory, branch audit/round2-v0.8, repo /home/mish/Projects/tcp_ping_prometheus",
  "windows_only_tests": [
    "TestIsPeerUnreachable_WindowsErrnos (internal/prober/unreachable_windows_test.go:15, //go:build windows) — winsock errno classification incl. WSAENETRESET and wrapped errnos; portable ECONNRESET must NOT classify",
    "TestHardenLogSink windows branches (main_test.go:596-602, 630-636, 649-666, runtime.GOOS-gated) — DACL on create / DACL repair / restrictLogDACL idempotence, asserted via verifyLogDACLRestricted (logacl_windows_test.go:32)"
  ],
  "windows_tagged_files_in_windows_job": true,
  "windows_job_command": "go test -count=1 -race -timeout 30m -v ./... (covers packages ., internal/prober, test)",
  "gaps": [
    "G1 P1: reapplyLogDACL (logacl_windows.go:29) — zero tests; headless-testable; sketch: seed/wide/nonexistent/empty-path cases + verifyLogDACLRestricted",
    "G2 P1: startLogDACLRecheck (logacl_windows.go:54, wired main.go:1004) — zero tests; requires const logDACLRecheckInterval -> var to test at short interval (DynClientTTL precedent)",
    "G3 P1: rotated-file DACL regression scenario — untested; sketch: harden -> rename (simulated lumberjack rotation) -> fresh file with dir DACL -> reapply -> verify restricted set on live file and untouched renamed file",
    "G4 P2: setDontFragment IPv6 branch (mtu_windows.go:65-72) and non-SyscallConn/non-UDPAddr guards never executed on Windows; sketch: [::1] loopback dial + setDontFragment nil + getsockopt IPV6_MTU_DISCOVER==IP_PMTUDISC_DO; scriptedReadConn guard test",
    "G5 P2: DSCP on Windows (dscp_other.go:13) error path and warn-and-continue in client (client.go:905-909) untested; sketch: setDSCP returns error + client with DSCP=46 still advances ProbesSent",
    "G6 manual-only: installer/windows .bat flows (delayed expansion, INSTALL_ARGS quoting, backslash strip, restart ladder) — needs SCM install/elevation/interactive prompts",
    "G7 manual-only: restrictLogDACL fail-closed on WRITE_DAC denial (logacl_windows.go:118-127)"
  ],
  "race_timeout_check": "OK today: observed 10-20min on windows runners under -race vs 30m go timeout (~1.5-3x headroom); job timeout-minutes 45 correctly exceeds it; soak test skips by default; new windows tests must use a var-reduced DACL recheck interval, never the real 5m const",
  "verdict": "OK with notes"
}
```