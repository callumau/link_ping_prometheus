## Review

Data verified (clean, no findings): all 22 registered metric names in `internal/prober/metrics.go` appear in README's metrics table with matching label sets, and no table row names a nonexistent metric; all 31 flags registered in `main.go` (main.go:59–90) appear in README's flags table with correct defaults; README states 2000/s per-IP + 10000/s global rate caps (server.go:64/66), 30s replay window (server.go:27), miss threshold 3 (prober.go:55), RTT buckets `{0.005…3.0}` (metrics.go:21), pending-window cap 1000 (prober.go:143), straggler wait 5s (client.go:177), /metrics+/status cap 2 (main.go:31), TTL 10m and 1024 CIDR-clients (server.go:53/74) — all match; `rules/link-monitor.yml` references only existing metric names/recording rules; the 20s service Stop deadline (main.go `svcStopDeadline`) is stated nowhere in README, so no mismatch exists. Four drifts found, all documentation omissions of newly-shipped user-facing behavior:

```
- Finding: P1 — README /status field list omits the new `straggler` JSON field
  Doc: README.md:640 (/status paragraph)
  Code: internal/prober/status.go:38-41 (`Straggler bool` → json `straggler`, set via MarkStraggler status.go:63-76)
  Mismatch: the enumeration "…`path_mtu_bytes` (…) and `last_echo_age_seconds` (…)" ends without `straggler`; a /status consumer has no documented meaning for the field (also omitted in the same enumeration: `jitter_seconds`, status.go:35).
  Fix: extend README.md:640 to "…`last_echo_age_seconds` (-1 until the first echo), `jitter_seconds`, and `straggler` (1 while that target's probe loop was replaced but failed to join within 5s and is still winding down — its last values are not live)".

- Finding: P2 — README omits the new periodic log-DACL re-apply (rotation regression fix)
  Doc: README.md:622 (flags table `-log-file` row), README.md:729 (checklist step 1), installer/windows/README.md:11-13 (step 3)
  Code: internal/prober/logacl_windows.go:18 (`logDACLRecheckInterval = 5 * time.Minute`), startLogDACLRecheck wired at main.go:1004
  Mismatch: all three sites describe DACL restriction as startup-only; README:729 even says "log rotation creates fresh files that inherit the directory ACL" implying a rotated live file stays wide until restart, while the code re-applies the restricted file DACL every 5m.
  Fix: add one sentence at each site: "This restriction is also re-applied every 5 minutes at runtime, so a rotation-regressed (wide-inherited) DACL is repaired without a service restart."

- Finding: P2 — README omits the new log-sink write-failure watcher
  Doc: README.md:720 (Windows hardening bullet "Lifecycle events in the Windows Event Log"), also absent from installer/windows/README.md step 4 (line ~19)
  Code: internal/prober/logsink.go:54 (`sinkCheckInterval = 30 * time.Second`), watchLogSink wired at main.go:1003 (error events to event log/stderr)
  Mismatch: bullet lists event-log content as "start, stop, and fatal errors" only; runtime log-sink write failures (disk full / log dir removed) surfaced every 30s are undocumented.
  Fix: extend README.md:720 to "start, stop, fatal errors, and log-sink write failures (checked every 30s while the service runs)".

- Finding: P2 — installer README omits the bounded wait loops and fatal (non-zero-exit) post-hardening steps
  Doc: installer/windows/README.md:28 (step 8 "Starts the service and prints its state") and :9 (script table row for uninstall-service.bat)
  Code: installer/windows/install-service.bat:85-93 (bounded 120s stop wait → exit 1), :104-105 (fatal upgrade-start failure → exit 1), :502-512 (bounded 60s RUNNING wait → exit 1); uninstall-service.bat:33-45 (bounded 120s stop wait → exit 1); further fatal steps at install-service.bat:284-299, 320-345, 453-470
  Mismatch: README says only "prints its state" / "Stop, remove service" — no mention that both scripts fail closed (non-zero exit) on stuck STOP_PENDING / SERVICE_STOPPED-after-start or that the waits are bounded (120s stop / 60s start); only the credential-key ACL step's fatality is documented today.
  Fix: rewrite step 8 as "Starts the service and waits up to 60s for RUNNING; all hardening steps (binary copy, log-dir ACL, SID, failure ladder, credential-key ACL, start) abort the script with an ERROR line and non-zero exit", and add to the uninstall row: "bounded 120s wait for STOPPED (non-zero exit if stuck)".
```

Merge verdict: OK with notes — no code drift found; these are documentation additions for behaviors shipped in the audit commits (all four sit exactly in the checked drift classes and none require code change). No files were modified; the complete artifact is above for persistence.