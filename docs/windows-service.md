# Windows

Use `-svc` to install, uninstall, start, stop, or run the agent. Runtime
flags are recorded at install time, except `-svc`, `-metrics-user`,
`-metrics-pass`, `-echo-secret` and `-echo-secret-old`. Credentials are
**not** persisted into the service config; set `LINK_PING_METRICS_USER` /
`LINK_PING_METRICS_PASS` and `LINK_PING_ECHO_SECRET` /
`LINK_PING_ECHO_SECRET_OLD` in the service environment instead (a warning
is printed at install time).

```sh
link_ping_prometheus.exe -mode=both -targets=targets.json -allow=192.0.2.11 -metrics=":2112" -log-file="C:\ProgramData\link_ping_prometheus\logs\service.log" -svc=install
```

## Built-in hardening (set at install)

- **Crash recovery:** SCM restarts 5s after a failure (reset period 24h).
  A crash or fatal internal error exits non-zero so recovery fires — as
  does a mid-run failure of the metrics HTTP server: if `/metrics`,
  `/status`, `/healthz` or `/readyz` die while probing continues, the agent
  exits non-zero.
- **Delayed auto-start**, depending on `Tcpip` (sockets) and `W32Time`
  (time sync; the HMAC replay window needs roughly NTP-synchronized
  clocks).
- **Event Log lifecycle events** (Application source `link_ping_prometheus`):
  start, stop and fatal errors stay visible with no log file. With
  `-log-file` set, log-sink write failures (disk full, log dir removed or
  ACL'd away) surface to the same log every 30s.
- **Credentials never persisted** into the service config.

## Windows Server version support

The agent runs as a service on any Windows the Go runtime supports; SCM
recovery, log rotation, HMAC and the UDP echo path have no version-specific
requirements. `-mtu-sweep` DF discovery supports IPv4 on every version
(Server 2003+ via `IP_DONTFRAGMENT`, falling back from `IP_MTU_DISCOVER` on
Server 2019+/Windows 10 1703+); IPv6 needs Server 2019+ (or Windows 10
1703+). Where an option is missing the sweep disables itself with a
one-time warning; probing is unaffected.

## Enterprise deployment checklist

`installer/windows/install-service.bat` / `uninstall-service.bat` automate
steps 1–4 (admin check, ACL'd log dir, escalating restart ladder,
per-service SID, credential prompts). Run elevated; a wizard asks for mode
(server/client/both), metrics address, targets (a JSON file or one
host:port), the **required** client IP allow-list for server/both modes, log
directory, and an optional service account, then shows a summary.

1. **Always pass `-log-file`.** Under the service stdout is discarded, so
   without a log file logs go nowhere (lifecycle/fatal events still reach
   the event log); a warning is printed. Rotation is built in
   (`-log-file-max-mb/-backups/-age`). The agent enforces `0600` on the log
   file at startup (repairing wider modes) and refuses symlinked paths. It
   also replaces the file's DACL with a protected set (no parent
   inheritance) granting full access only to `SYSTEM`, `Administrators` and
   its own account, wherever `-log-file` points. The installer's ACL'd log
   **directory** is defense-in-depth; the manual recipe remains useful:

   `icacls "<dir>" /inheritance:r /grant "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "NT SERVICE\link_ping_prometheus:(OI)(CI)M"`
   (SIDs, not account names: `Administrators` is localized and icacls cannot
   resolve it on a non-English host.)

   The restriction is re-applied every 5 minutes at runtime, repairing a
   rotation that recreates the live file under a wide directory DACL.
2. **Service account.** The service installs as `LocalSystem`, more
   privilege than the prober needs (outbound UDP, a metrics port, its log
   directory). Switch to a passwordless built-in or gMSA account after
   install for least privilege:

   ```sh
   sc.exe config link_ping_prometheus obj= "NT AUTHORITY\LocalService"
   ```

   Use `NT AUTHORITY\NetworkService` if firewalls expect machine-account
   identity, or a gMSA (`DOMAIN\svc-linkping$`) if policy mandates managed
   accounts, and grant write access to the log directory only. **Delete (or
   re-ACL) an existing log file before switching accounts**: the agent
   restricts the file's DACL to SYSTEM + Administrators + its creating
   account, so the previous account's file denies the new one and the
   service exits non-zero at startup (the restart ladder loops until the
   file is removed).
3. **Secrets delivery.** Set the credential environment variables
   machine-wide (System Properties → Environment Variables) or per-service:

   ```sh
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_METRICS_USER /t REG_SZ /d <user> /f
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_METRICS_PASS /t REG_SZ /d <pass> /f
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_ECHO_SECRET /t REG_SZ /d <secret> /f
   ```

   The installer and the Ansible play restrict this key's ACL to SYSTEM and
   Administrators once a value is stored (inheritance off). Run the same
   snippet by hand if you add values with `reg add`, and confirm a non-admin
   `reg query` of the key fails. Treat values present before that hardening
   as disclosed: rotate the echo secret and metrics password (the Security
   rotation runbook), then restart. The echo secret must be at least 16
   characters — the HMAC-SHA256 key material, brute-forceable if shorter
   (the wizard enforces this; no binary-side minimum).
4. **Further hardening (optional).** The installer applies the restart
   escalation ladder (`sc.exe failure ... actions=
   restart/5000/restart/30000/restart/60000`), the per-service SID
   (`sc.exe sidtype link_ping_prometheus unrestricted`) and the log-dir ACL.
   Manual only: restrict reconfiguration with `sc.exe sdset`; keep the
   binary under `%ProgramFiles%` with Admins-only write ACLs;
   Authenticode-sign it and allowlist via AppLocker/WDAC. A hand-install
   (`<binary> -svc=install`, no wizard) gets one restart action (uniform 5s
   retry, 24h failure-reset — what the kardianos path can express); the
   escalating 5s/30s/60s ladder needs the wizard's `sc.exe failure` step.
5. **Upgrades.** Re-run `installer/windows/install-service.bat` with the
   new binary: it detects the service, swaps the binary only when its
   SHA256 differs, and restarts (`link_ping_build_info` reports the new
   runtime). Parameters are preserved; if runtime flags changed, uninstall
   and reinstall. Verify the release first, in this order:

   ```sh
   # 1. the signature: who published this checksums file (keyless sigstore)
   cosign verify-blob --bundle checksums.txt.sigstore.json \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-identity "https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/<tag>" \
     checksums.txt
   # 2. the artifacts: against the now-trusted checksums file
   sha256sum --check --ignore-missing checksums.txt
   # 3. the provenance: this release workflow built the artifact (GitHub
   #    attestation store). The cosign signature above only proves who
   #    published the checksums file; the SLSA provenance attestation
   #    proves which workflow run built each artifact, on what runner,
   #    from what source commit — a swapped or out-of-pipeline artifact
   #    fails this check even if the signature itself verifies.
   gh attestation verify link_ping_prometheus_Linux_x86_64.tar.gz \
     -R callumau/link_ping_prometheus
   ```
6. **Supply chain and fleet-wide auth, before scaling out:**
   - Restrict who can create `v*` tags with a GitHub Ruleset: the release
     build reads the tag for `link_ping_build_info` and mints a sigstore
     signing identity, so tag creation is release-authoring permission.
     `.github/CODEOWNERS` lists the release paths — replace its placeholder
     team first (an unresolved handle matches nobody, so a required-review
     ruleset on it is never satisfiable).
   - Pin the WinRM CA per host in the Ansible inventory
     (`deploy/ansible/inventory.example.yml`); an unpinned `winrm`
     connection trusts whatever CA answers first.
   - Clock sync is load-bearing: `-echo-secret` rejects any probe more than
     30s from the reflector's clock, so a drifted node drops its own
     legitimate probes as replay and its peers read `link_up=0`.
     `LinkClockSkewHigh`, `LinkClockSkewCritical` and `ServerReplayDrops`
     in `rules/link-monitor.yml` alert on it.
