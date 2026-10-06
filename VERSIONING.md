# Versioning policy

The release version comes from a `v*` git tag on `main`; GoReleaser bakes it
into the binary via `-X main.version=`. Tags are the only version authority —
never hardcode a version anywhere else.

## Phase 1 — 0.x (now, until v1)

0.x is pre-stability: **a minor bump may contain breaking changes** — that is
the 0.x contract. The discipline is about signaling, not guarantees:

- **Patch `0.X.Y`** — bug fixes with **no observable change**: metric
  semantics, defaults, CLI flags, alert expressions, wire behavior and
  deployment-tooling acceptance all untouched. Safe to auto-bump.
- **Minor `0.X.0`** — everything else: features, new metrics/alerts,
  deliberate behavior changes (e.g. a reload restart now counting abandoned
  probes as timeouts), and tooling that may now *reject* previously-accepted
  configs (symlinked log paths, wildcard metrics binds). Release notes are
  mandatory; operators should read them before upgrading.

Litmus test for patch vs minor: *if an operator could notice the change
without reading the notes, it is not a patch.*

## v1.0.0 — the stable, hardened promotion gate

v1.0.0 is a promise of stability, not a birthday. Every item below must hold
and be provable (CI green, tests in-repo, or field evidence):

1. **Wire protocol frozen.** The 24/32-byte datagram, HMAC tag and ±replay
   window are unchanged across the last two minors and none are pending. Any
   later change is a MAJOR with a compatibility story.
2. **Metrics contract frozen.** Names, label sets, types, `Help` strings and
   RTT bucket edges fixed. The parity tests pin README ↔ code on both.
3. **Security posture complete.** `govulncheck` clean; the audit round
   closed (all findings fixed or explicitly filed); HMAC/replay,
   fail-closed allowlist and metrics auth covered by table-driven tests.
4. **Field maturity.** ≥30 days of continuous multi-target operation in
   production-like conditions: flat heap (soak-test ceiling), zero
   straggler/reader-dead/internal-error drift above baseline, zero
   crash-loops or unclean service exits.
5. **Upgrade paths proven.** v0.6/v0.7 → v1.0.0 with zero config edits:
   Windows service upgrade, HMAC rotation (`-echo-secret-old`), targets
   hot-reload.
6. **Docs parity.** README flags table, operational numbers and the Windows
   checklist match code and installer — the tests enforce this.

## Phase 2 — after v1.0.0 (strict semver)

- **MAJOR** — breaking: removing/renaming a flag or metric, changing metric
  semantics or the wire format, dropping a platform. **Deprecation rule:**
  anything removed is first announced at startup (log Warning) and in the
  README for at least one minor release.
- **Minor `1.X.0`** — additive only: new flags defaulting to current
  behavior, new metrics (cardinality budget respected), new alert rules,
  tooling hardening that stays backwards-compatible.
- **Patch `1.X.Y`** — fixes. Security fixes ship as patches even when they
  change internals (semver's security exception), but semantics-affecting
  security fixes must be called out in the release notes.

Rules of thumb: operators should never be surprised by a patch; should never
find a removed flag in a minor; and v1 exists so that a minor is boring.
