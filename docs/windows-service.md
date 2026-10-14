# Windows

Use `-svc` to install/uninstall/start/stop/run. The tool records runtime flags at install time (excluding `-svc`, `-metrics-user`, `-metrics-pass`, `-echo-secret`, and `-echo-secret-old`). Metrics auth credentials and HMAC secrets are **not** persisted into the service configuration; set `LINK_PING_METRICS_USER` / `LINK_PING_METRICS_PASS` and `LINK_PING_ECHO_SECRET` / `LINK_PING_ECHO_SECRET_OLD` in the service environment instead (a warning is printed at install time).

```sh
link_ping_prometheus.exe -mode=both -targets=targets.json -allow=192.168.1.71 -metrics=":2112" -log-file="C:\ProgramData\link_ping_prometheus\logs\service.log" -svc=install
```

**Built-in service hardening (configured automatically at install):**

- **Crash recovery**: SCM failure action is *restart* after 5s (reset period 24h). A crash or fatal internal error exits non-zero so recovery fires — a dead monitor never stays down silently. This includes a mid-run failure of the metrics HTTP server itself: if `/metrics`, `/status`, `/healthz` or `/readyz` die while the agent keeps probing, the agent exits non-zero so the restart ladder brings the whole monitor back (probing without a metrics endpoint is dead weight that looks healthy).
- **Delayed auto-start** with dependencies on `Tcpip` (sockets) and `W32Time` (time sync — the HMAC replay window requires roughly NTP-synchronized clocks between nodes).
- **Lifecycle events in the Windows Event Log** (Application source `link_ping_prometheus`): start, stop, and fatal errors are visible even with no access to the log file. When `-log-file` is configured, runtime log-sink write failures (disk full, log directory removed or ACL'd away) are surfaced to the same event log every 30s while the service runs — otherwise a dead sink is indistinguishable from silence.
- **Credentials never persisted** into the service configuration.

**Windows Server version support:** the agent runs as a service on any Windows the Go runtime supports; SCM recovery, log rotation, HMAC and the UDP echo path have no version-specific requirements. The optional `-mtu-sweep` DF discovery supports IPv4 targets on every Windows Server version (Server 2003+ via the classic `IP_DONTFRAGMENT` option, falling back from the richer `IP_MTU_DISCOVER` path-MTU option available on Server 2019+/Windows 10 1703+); IPv6 targets need Windows Server 2019+ (or Windows 10 1703+). On Windows versions lacking a needed option the sweep alone disables itself with a one-time warning — probing is unaffected.

**Enterprise deployment checklist:**

> `installer/windows/install-service.bat` / `uninstall-service.bat` in this repo automate steps 1–4 below (admin check, ACL'd log dir, escalating restart ladder, per-service SID, credential prompts). Run from an elevated prompt: an interactive wizard asks for mode (server/client/both), metrics address, targets — a JSON file or a single host:port — the **required** client IP allow-list for server/both modes, log directory, and optional service account, then shows a summary before installing.

1. **Always pass `-log-file` at install.** Under the service, stdout is discarded; without a log file, verbose logs go nowhere (lifecycle/fatal events still reach the event log). Log rotation is built in (`-log-file-max-mb/-backups/-age`). A warning is printed if you skip it. The agent enforces `0600` on the log file at startup (repairing wider modes) and refuses symlinked log paths — place the log in a directory not writable by other local users (the installer's ACL'd log dir satisfies this). On Windows `chmod` cannot restrict a DACL, so the agent does the equivalent itself: at startup it replaces the log file's DACL with a protected set (no parent inheritance) granting full access only to `SYSTEM`, `Administrators` and the account the agent runs as, wherever `-log-file` points — a manual install now inherits no wide directory grant. The ACL'd log **directory** created by the installer remains defense-in-depth (log rotation creates fresh files that inherit the directory ACL), and the manual `icacls` recipe below stays useful for belt-and-braces (`icacls "<dir>" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "NT SERVICE\link_ping_prometheus:(OI)(CI)M"`). The restriction is also re-applied every 5 minutes at runtime, so a lumberjack rotation recreating the live file under a wide directory DACL is repaired without a service restart.
2. **Service account.** By default the service installs as `LocalSystem`, which is more privilege than this prober needs (outbound UDP + a metrics port + its log directory). For least privilege, switch to a passwordless built-in or gMSA account after install:

   ```sh
   sc.exe config link_ping_prometheus obj= "NT AUTHORITY\LocalService"
   ```

   Use `NT AUTHORITY\NetworkService` instead of LocalService if network firewalls expect machine-account identity, or a domain gMSA (`DOMAIN\svc-linkping$`) if policy mandates managed accounts. Grant the chosen account write access to the log directory only. **If a log file already exists, delete it (or re-ACL it) before switching accounts**: the agent restricts the log file's DACL to SYSTEM + Administrators + the account that created it, so the *previous* account's log file denies the new account write access and the service exits at startup (loud, non-zero — the restart ladder will loop until the file is removed).
3. **Secrets delivery.** Set the credential environment variables machine-wide via System Properties → Environment Variables, or per-service:

   ```sh
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_METRICS_USER /t REG_SZ /d <user> /f
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_METRICS_PASS /t REG_SZ /d <pass> /f
   reg add HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment /v LINK_PING_ECHO_SECRET /t REG_SZ /d <secret> /f
   ```

   The installer and the Ansible play both restrict this key's ACL to SYSTEM and Administrators once a value has been stored (inheritance off, so the inherited world-readable entry is dropped); run the same PowerShell snippet by hand if you add values with `reg add` yourself, and confirm a non-admin `reg query` of the key now fails. Values that sat in the key before that hardening should be treated as disclosed: rotate the echo secret (and metrics password) with the outage-free rotation runbook in the Security section, then restart the service. For higher assurance still, prefer an ACL-hardened secrets file sourced by your configuration management over the registry. The echo HMAC secret should be at least 16 characters regardless of how it is delivered — it is the key material for HMAC-SHA256 probe authentication and a short value is brute-forceable (the install wizard enforces this; there is no binary-side minimum).
4. **Further hardening (optional, post-install):** the restart escalation ladder (`sc.exe failure ... actions= restart/5000/restart/30000/restart/60000`), the per-service SID (`sc.exe sidtype link_ping_prometheus unrestricted`) and its log-dir ACL are applied automatically by the installer; the manual `sc.exe` recipes above are for a hand-install or re-verification. Only the following remain manual: restrict who can reconfigure the service via `sc.exe sdset`; keep the binary under `%ProgramFiles%` with Admins-only write ACLs; Authenticode-sign the binary and allowlist via AppLocker/WDAC.

   Note that a hand-install (`<binary> -svc=install`, no wizard) gets exactly ONE restart action (uniform 5s retry, 24h failure-reset period — what the kardianos install path can express); the installer's escalating 5s/30s/60s ladder requires the wizard's post-install `sc.exe failure` step above. The agent's own fatal-error behavior (non-zero unclean exit under the service so SCM recovery fires) is identical either way.
5. **Upgrades:** re-run `installer/windows/install-service.bat` with the new binary — it detects the existing service, swaps the binary only when its SHA256 differs, and restarts (runtime truth updates via `link_ping_build_info`). Parameters are preserved. If any runtime flags changed, uninstall and reinstall instead — arguments are snapshotted at install time. Before running the installer (it is elevated and writes a service, so a tampered binary lands with SYSTEM rights), verify the release in this order:

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
   - Restrict who can create `v*` tags with a GitHub Ruleset — the release build reads the tag for `link_ping_build_info` and now also mints a sigstore signing identity from the run, so tag creation is release-authoring permission, not a general contributor one. `.github/CODEOWNERS` lists the release paths (replace its placeholder team first — an unresolved handle matches nobody, so a required-review ruleset on it would never be satisfiable).
   - Pin the WinRM CA per host in the Ansible inventory (`deploy/ansible/inventory.example.yml`); an unpinned `winrm` connection trusts whatever CA answers first, which is the deploy host's supply chain.
   - Clock sync is load-bearing, not hygiene: `-echo-secret` rejects any probe more than 30s from the reflector's clock, so a drifted node drops its own legitimate probes as replay and its peers read `link_up=0`. `LinkClockSkewHigh`, `LinkClockSkewCritical` and `ServerReplayDrops` in `rules/link-monitor.yml` alert on it — load them everywhere the service runs.
