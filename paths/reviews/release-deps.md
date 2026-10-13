All evidence gathered from the repo itself (go.mod, go.sum, imports, CI pin, usage sites). Per session constraints, I ran no commands and performed no web lookups — all version-latest / maintenance-status / changelog-diff claims are marked UNVERIFIED for the parent to confirm.

# Dependency Audit & Upgrades — Pre-Release Review

Repo: `link_ping_prometheus` · go 1.25.0 / toolchain go1.27.1 · audited from working tree at HEAD (no commands run, no files modified).

## Per-dependency verdicts

### `github.com/kardianos/service v1.2.4` — **KEEP** (evaluate v1.3.0 post-release)

**How it's used** (verified):
- `main.go:38` + `logsink.go:11` — the only two import sites.
- `main.go:550–567` `serviceConfig()`: `service.Config{Name, DisplayName, Description, Dependencies:["Tcpip","W32Time"], Option:{"StartType","DelayedAutoStart","OnFailure":"restart","OnFailureDelayDuration":"5s","OnFailureResetPeriod"}}` — this is the SCM hardening pinned by `TestServiceConfigHardening`.
- `main.go:649` `service.New`, `main.go:693–760` `program` implements `service.Interface` (Start/Stop), `SystemLogger` used twice (main.go:723, 735) so sink failures reach the Windows event log. Install path rebuilds the SCM command line with credential flags stripped.
- `logsink.go` imports the package only for the `service.Service` handle type passed to `SystemLogger`.

**Replacement by stdlib?** No. `golang.org/x/sys/windows/svc` exists but has no install/uninstall, no OnFailure recovery-action mapping, no DelayedAutoStart option, and no SystemLogger wrapper — hand-rolling that is a large, Windows-only, high-risk rewrite. Staying is strictly lower risk.

**Upgrade to v1.3.0?** UNVERIFIED (parent must fetch): read the changelog/commit diff v1.2.4→v1.3.0 on GitHub, specifically:
1. `service_windows.go` — mapping of `OnFailure`/`OnFailureDelayDuration`/`OnFailureResetPeriod` to `SC_ACTION` and the `DelayedAutoStart` registry write. This repo's recovery ladder and installer script (`installer/windows/`) are load-bearing and cross-checked against `TestServiceConfigHardening` + the native windows-latest CI job, which would catch a mapping regression — that's the safety net making an upgrade *survivable*, but not a reason to do it pre-release.
2. `Run()`/`systemExit` semantics — AGENTS.md pins that fatal run errors must exit non-zero (unclean) so SCM recovery fires; any change to exit-code propagation would silently break the restart ladder.
3. `SystemLogger` / Logger API shape — used at main.go:723/735.

No known CVEs in kardianos/service (UNVERIFIED — parent should confirm via govulncheck + GitHub advisories). **Verdict: no observable benefit to this repo; defer.**

### `github.com/prometheus/client_golang v1.23.2` — **KEEP** (optional patch-bump if a v1.23.x > .2 exists)

**How it's used** (verified): `prometheus` (Counter/Vec/Gauge/Histogram/Registry/DefaultRegisterer) in main.go, internal/prober/{client,server,metrics}.go and all tests; `promhttp.HandlerFor` with `DisableCompression` + `MaxRequestsInFlight: maxConcurrentScrapes` and `promhttp.InstrumentMetricHandler` at main.go:804–815. These are stable, long-lived APIs — a patch bump is behaviorally inert; a minor bump could touch promhttp pooling behavior the repo has tuned around (gzip-off default, 503 body wording mirrors promhttp's, main.go:869).

Latest version / known promhttp issues with Go 1.27: UNVERIFIED. The repo's own comment trail (main.go:795–815) already encodes the known promhttp gzip-pool-per-P behavior. No CVE in client_golang is known to affect this surface (the 2022 promhttp range-denial CVE predates v1.23; UNVERIFIED via govulncheck — CI already runs it clean at HEAD).

### `github.com/prometheus/client_model v0.6.2` — **KEEP**

Direct require is correct despite test-only imports: `dto "github.com/prometheus/client_model/go"` is imported from `main_test.go:9`, `test/{helpers,metrics,reload}_test.go`, and `internal/prober/{client_hmac,client_recovery,client_retry}_test.go`. Test files in the main module count as direct imports for `go mod tidy`. v0.6.2 is the current line to my knowledge (UNVERIFIED); it is also the release that uses `google.golang.org/protobuf` (already indirect at v1.36.8). Nothing to do.

### `gopkg.in/natefinch/lumberjack.v2 v2.2.1` — **KEEP** (do NOT hand-roll)

**How it's used** (verified): exactly one construction site, `main.go:320–327` — `Filename, MaxSize, MaxBackups, MaxAge, Compress:false`, wrapped in `io.MultiWriter(lj, os.Stdout)` and then `countedWriter` (logsink.go). Plus the surrounding hardening the repo built *because of* lumberjack's behavior:
- `main.go:290–302` `hardenLogSink` enforces 0600 pre-open because "lumberjack re-opens pre-existing files with no mode check and copies the live file's mode onto every rotated artifact";
- `logacl_windows.go:22–28` re-applies the DACL after each rotation because the fresh live file is recreated;
- `main.go:1001` comment pins the known regression mode.

**What lumberjack actually provides beyond reopen+rename+compress:** atomic size-triggered rotation splitting a single `Write` across the boundary, timestamped-unique backup naming, Windows-open-handle rename handling, MaxBackups/MaxAge cleanup of stale backups, mutex-serialized writes, and concurrent-writer safety. Those edge cases (disk-full mid-rotate, rename-on-Windows failure, partially-written rotation) are precisely where hand-rolled rotators break, and the repo's DACL/mode repair logic is coupled to lumberjack's exact rotation semantics ("after the first lumberjack rotation…" comment in logacl_windows.go). A ~600-line hand-rolled rotator = new untested failure surface in the logging path, saving one dormant dependency with no known CVEs (UNVERIFIED). Maintenance status (last commit/release) UNVERIFIED — but dormancy is low-risk for a leaf writer with a frozen API and the repo's Compress=false usage. **Replacement is negative value-per-risk pre-release.**

### `golang.org/x/sys v0.47.0` — **KEEP** (bump opportunistically with `go mod tidy`)

Direct and irreducible: `golang.org/x/sys/windows` in `logacl_windows.go:12`, `mtu_windows.go:10`, `unreachable_windows.go:5` (+ test files), `golang.org/x/sys/unix` in `mtu_linux.go:10`, `dscp_linux.go:10` (+ tests). These need raw syscalls (WSAIoctl DF flag, IP_DSCP, DACL via SecurityDescriptor) — no stdlib equivalent. Latest release UNVERIFIED (x/sys releases track Go toolchains; v0.47.0 is recent enough that a newer patch likely exists but is immaterial). No known vulns in x/sys (UNVERIFIED).

## Indirect deps — anything droppable?

No. From go.mod's indirect block: `beorn7/perks`, `cespare/xxhash/v2`, `prometheus/common v0.66.1`, `prometheus/procfs v0.17.0`, `go.yaml.in/yaml/v2 v2.4.2`, `google.golang.org/protobuf v1.36.8` are all genuine edges of client_golang. `kr/text v0.2.0` / `munnerz/goautoneg` — goautoneg is a real promhttp content-negotiation edge; kr/text is lifted only because the yaml.v2 → check.v1 → kr/pretty → kr/text chain runs through incomplete (pre-1.17-pruning) go.mod files (go.sum confirms kr/pretty, rogpeppe/go-internal, check.v1 present as graph-only entries). Dropping it would require upstream go.mod changes — not possible, and it ships no code into the build. Confirms the parent's prior framing: fine as indirect.

**`go mod tidy` prediction:** go.mod unchanged; go.sum expected unchanged — note `klauspost/compress v1.18.0` has an `h1:` hash in go.sum but no go.mod require, which is consistent (pruned graph: it's a build package of client_golang/promhttp, version recorded in client_golang's complete go.mod; only its hash lands in ours). If tidy *does* want to add it to go.mod or shuffle go.sum lines, that itself is a signal to re-audit — treat any tidy diff as a finding. UNVERIFIED (no commands run).

**protobuf v1.36.8 indirect:** well past the known protojson DoS fixes (GO-2024-2611 → fixed v1.33); no action.

## govulncheck pin

CI pins `golang.org/x/vuln/cmd/govulncheck@v1.7.0` (.github/workflows/ci.yml:105), bumped deliberately from v1.1.4 because the old scanner panicked parsing go1.27 source (git log commit "fix(ci): bump govulncheck pin…"). Whether v1.7.0 is still the latest stable release is UNVERIFIED from this session — parent should check `golang.org/x/vuln` releases. If a newer scanner exists, bump it in its own commit per the CI comment's convention ("Bump the version in its own commit"); a stale-but-functional scanner pin is not a release blocker since it's the scanner, not the vuln DB, that's pinned (the DB is fetched live).

## Review summary

```
## Review
- Correct: direct-require set is minimal and honest — client_model direct despite
  test-only imports is what tidy requires; x/sys is irreducible (DACL/DF/DSCP
  syscalls); every indirect edge is genuine.
- Correct: no dep in the set has a known-reachable CVE; CI runs govulncheck
  ./... on every push, which is the authoritative check for reachable vulns.
- Finding: P2 — kardianos/service v1.3.0 exists; changelog/diff not inspected
  (no web tool this session). The repo's exposure is exactly three surfaces:
  SCM option mapping (service_windows.go), Run() exit-code semantics (restart
  ladder depends on unclean exits), SystemLogger. Defer; TestServiceConfigHardening
  + the native windows-latest job are the regression net if/when upgraded.
- Finding: P2 — lumberjack maintenance status unverified; even if dormant,
  replacement is negative value-per-risk (rotation edge cases + coupled
  DACL/mode-repair logic in hardenLogSink/logacl_windows.go).
- Finding: P2 — UNVERIFIED placeholders requiring parent web lookups:
  latest client_golang release (any v1.23.x > .2), latest x/sys, latest x/vuln
  (is v1.7.0 still current), kardianos/service v1.3.0 changelog, lumberjack
  last-commit date, GitHub advisories for all five.
- Merge verdict: OK with notes — for the dependency lane specifically:
  no upgrade is required for release; keep everything at current pins.
```

## Recommended action list (value-per-risk order, pre-release pass)

1. **No-op (do nothing)** — the current pin set has no known reachable vulnerability and no upgrade in the set delivers observable value. Zero-risk.
2. Run `go mod tidy && git diff -- go.mod go.sum` to confirm zero drift (validates the klauspost/compress go.sum reasoning above). Near-zero risk; catches silent graph rot.
3. Verify govulncheck v1.7.0 is still the current x/vuln stable release; if not, bump in its own commit (repo convention). Low risk; keeps the release gate honest.
4. Web-verify the UNVERIFIED items (latest client_golang/x/sys patches, GitHub advisories, lumberjack commit date). If a client_golang patch release exists beyond v1.23.2, take it as a patch bump — inert at the API surface used (HandlerFor/InstrumentMetricHandler/DisableCompression/MaxRequestsInFlight).
5. **Post-release, not pre-release:** evaluate kardianos/service v1.3.0 by diffing `service_windows.go` (recovery-action mapping, DelayedAutoStart) and Run/exit semantics against v1.2.4; the hardening test and windows CI job make the upgrade verifiable, but there is no pull to do it now.
6. **Do not** replace lumberjack with a hand-rolled rotator; do not replace kardianos/service with x/sys/windows/svc; do not touch the indirect set.