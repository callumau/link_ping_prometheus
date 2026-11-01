# Code signing policy

**Free code signing provided by [SignPath.io](https://about.signpath.io),
certificate by [SignPath Foundation](https://signpath.org).**

This policy covers the Windows executables published in the
[GitHub releases](https://github.com/callumau/link_ping_prometheus/releases) of
this repository.

## Scope

| Artifact | Signed | Notes |
|---|---|---|
| `link_ping_prometheus_Windows_*.zip` (the `link_ping_prometheus.exe` inside) | yes, once a SignPath project is approved | Authenticode, SHA-256, timestamped |
| `link_ping_prometheus_Linux_*.tar.gz`, `link_ping_prometheus_Darwin_*.tar.gz` | no | Linux and macOS do not use Authenticode; integrity is covered by the signed checksums below |
| `checksums.txt`, container image | yes (keyless cosign + SLSA attestation, independent of SignPath) | verify with `cosign verify-blob` / `gh attestation verify` |

Releases published before the SignPath project is approved are **unsigned**.
An existing release does not become signed retroactively; only releases built
after the integration is enabled carry the signature.

## Team roles

This is a single-maintainer project. The same person holds every role, and the
repository's permission model is the authority (not a separate team list):

- **Authors** (may push to the repository): [@callumau](https://github.com/callumau)
- **Reviewers** (review every change from a non-author): [@callumau](https://github.com/callumau)
- **Approvers** (approve each signing request): [@callumau](https://github.com/callumau)

Changes proposed by anyone who is not the author are merged only through a pull
request that the reviewer has read, including the workflow files and build
scripts — SignPath verifies that a signed binary was built from this repository
by this pipeline, so CI configuration is part of the reviewed surface.

## Build and signing process

1. A maintainer pushes a `v*` tag on `main`.
2. [`release.yml`](.github/workflows/release.yml) runs the test suite in a
   separate read-only job, then builds and packages the binaries with
   GoReleaser from that tag.
3. The Windows binaries carry a PE VERSIONINFO resource (product name
   "Link Ping Prometheus", product version = the release version), generated
   from [`installer/windows/versioninfo.json`](installer/windows/versioninfo.json).
4. The Windows archives are submitted to SignPath, where a **manual approval by
   the approver above** is required for every signing request.
5. The signed artifacts are published to the GitHub release.

`.github/workflows/release.yml` and `installer/windows/` are the files that can
change what gets signed; review them with that in mind.

## Privacy policy

This program transfers no information to other networked systems unless
specifically requested by the user or the person installing or operating it:

- It sends fixed-format UDP echo probes **only** to the targets the operator
  configures (`-target` / `-targets`), and echoes back only probes from sources
  on its fail-closed `-allow` list.
- It serves `/metrics`, `/status`, `/healthz` and `/readyz` on the listener the
  operator configures (loopback by default).
- It writes an optional log file at the path the operator chooses.
- It contains no telemetry, analytics, update check, or crash reporting.

## What this software is not

SignPath Foundation does not sign tools that exploit or scan for vulnerabilities.
link_ping_prometheus is a latency and packet-loss monitor, not a security
scanner:

- It speaks one fixed protocol (24/32-byte `LNKPING` datagrams) to explicitly
  configured endpoints and measures round-trip time, loss and jitter.
- It performs no port scanning, service enumeration, vulnerability detection,
  credential access, or exploitation, and it cannot be pointed at a range of
  addresses (targets are an explicit list; the allowlist is fail-closed).
- The optional MTU sweep sends DF-set probes of increasing size to the same
  configured target to find the path MTU.
