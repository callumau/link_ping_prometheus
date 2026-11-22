# Windows service installer

Batch scripts to install/uninstall `link_ping_prometheus.exe` as a hardened
Windows service. Run from an **elevated** prompt, with the `.exe` in this folder
(or edit `EXE_PATH` at the top of the script).

| Script | Purpose |
| --- | --- |
| `install-service.bat` | Fresh install, or in-place upgrade when a newer binary is provided |
| `uninstall-service.bat` | Stop and remove the service, event-log source, credential env vars, and a wizard-custom log directory |

`uninstall-service.bat` reads a wizard-custom log directory back from the
persisted service arguments. It waits up to a bounded 120s for STOPPED and exits
non-zero if the service is stuck.

## What install-service.bat does

1. Verifies admin rights and binary presence.
2. Copies the binary into `%ProgramFiles%\link_ping_prometheus` — an
   Admins-only-write location, since weak binary-path ACLs are the classic
   Windows service-persistence attack.
3. Creates an ACL-hardened log directory
   (`C:\ProgramData\link_ping_prometheus\logs`). The agent hardens the log
   **file** itself as well: at startup, `hardenLogSink` replaces the file's DACL
   with a protected set granting full access only to `SYSTEM`, `Administrators`
   and the account the agent runs as.

   The directory ACL remains defense-in-depth, since log rotation creates fresh
   files that inherit the directory ACL, not the hardened one.
4. Installs via `-svc=install`, which bakes in:
   - SCM recovery: restart on failure after 5s.
   - Delayed auto-start; dependencies on `Tcpip` and `W32Time`.
   - Event Log source (`Application` → `link_ping_prometheus`) for
     lifecycle/fatal events.
   - Credentials are never persisted into the service config.
5. Post-install hardening:
   - Escalating restart ladder: 5s → 30s → 60s, failure counter resets daily.
   - Per-service SID (`sc sidtype unrestricted`) granted write access only to
     the log directory.
6. Prompts for optional credential environment variables
   (`LINK_PING_METRICS_USER/PASS`, `LINK_PING_ECHO_SECRET`) — Enter skips.
7. Restricts the ACL on the credential registry key (see below).
8. Starts the service and waits up to 60s for RUNNING (prints its state).

All hardening steps fail closed: any failure — binary copy, log-dir ACL/SID
grant, start — aborts the script with an `ERROR` line and a non-zero exit, never
a silent "Done."

**Re-running the installer on an existing installation performs an in-place
upgrade.** The new binary is SHA256-compared against the installed one:
identical is a no-op, different stops the service, swaps only the binary, and
restarts.

All existing parameters are kept untouched.

Edit the VARIABLES section at the top for binary/install paths; everything else
is asked interactively: mode (server/client/both), metrics address, targets — a
JSON file or a single host:port endpoint — the required client IP allow-list for
server/both, log directory, optional service account, and a summary/confirm step
before anything is installed.

**Input validation.** Typed values are rejected when they contain a double-quote
or an ampersand — those characters cannot be delivered safely through the
script's quoted expansions (`reg add /d "..."`, the service argument list,
summary echoes). The metrics listen address is quoted into the argument list
like the other free-text values.

A trailing backslash is stripped from path values (it would escape the closing
quote). The echo HMAC secret (and its rotation predecessor) must be at least 16
characters: it is the key material for HMAC-SHA256 probe authentication, and a
short value is brute-forceable.

## Credential storage and the `Environment` value

The credential flags are deliberately stripped from the persisted service
config, so the SCM's per-service environment is the only delivery path for the
echo HMAC secret and the metrics Basic-auth password. That environment is a
**`REG_MULTI_SZ` value** on the service key:

```text
HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus
    Environment    REG_MULTI_SZ    LINK_PING_ECHO_SECRET=...\0LINK_PING_METRICS_USER=...
```

It is a **value, not a subkey**. An `Environment` *subkey* full of `REG_SZ`
values — which is what `win_regedit` produces by default, and what this
project's installer and plays used to write — is completely ignored by the SCM.
The agent then starts with no credentials: metrics auth is off, HMAC is not
enabled, and nothing in the configuration looks wrong. That is why the
mechanism is spelled out here and pinned by the e2e below.

Windows gives the service key an inherited ACL that lets **every local user**
read it, so `install-service.bat` protects the key first and only then writes
the value. The DACL carries both an inheriting pair (subkeys) and a plain pair
(the key itself — an ACE that only inherits does not grant on the key):

- `SYSTEM` — full control
- `BUILTIN\Administrators` — full control
- No per-service SID grant: the service process never reads this key. The SCM
  reads it as LocalSystem and injects the entries into the service
  environment, so a custom service account is unaffected.

**Verifying delivery.** The SCM reads the value at service start, so a restart
picks up changed values. Two smoke checks that the values actually reached the
service:

- with metrics credentials set, the endpoint answers **401** without
  credentials and **200** with `LINK_PING_METRICS_USER`/`LINK_PING_METRICS_PASS`;
- with an echo secret set, the peer's `link_server_clock_skew_seconds` appears
  (it is only exported for HMAC-authenticated frames) and
  `link_probes_sent_total` starts moving on a 32-byte frame (MTU sweep reports
  `1432` instead of `1424`).

The gated Windows e2e suite asserts the same automatically
(`LPP_E2E_WINDOWS=1 go test -run TestE2EWindowsCredentialEnvDelivery ./test/e2e/`),
writing the values as a multi-string on a real SCM-started service. It is not
run by CI: the service start path needs an elevated host with a working SCM,
which the hosted runners do not provide.

The step fails loudly: if the key cannot be protected or the value cannot be
written, the installer prints an `ERROR` line and exits non-zero.

A non-administrator querying the service key (for example
`reg query HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus /v Environment`)
gets **access denied**. Administrators still read the plaintext values, which
includes every account that can take the machine over. Protecting the service
key also removes non-administrator read access, so `sc query` from a standard
account stops working — the intended trade-off.

**Rotation.** The values are plaintext: anything that could read the key before
the ACL step (or while the ACL was still inherited) can still use the secret.
Treat the secret as compromised and rotate it — the zero-downtime rotation
runbook (new secret + previous secret in the service environment, then drop the
old one) is in the [security guide](../../docs/security.md).

The wizard's own "previous, for rotation" prompt writes
`LINK_PING_ECHO_SECRET_OLD` for exactly that runbook. Rotate the metrics password
by replacing the entry and restarting the service.

**Sites that manage registry ACLs by policy.** The installer's snippet is
exactly what a GPO-driven equivalent should apply, and it can be re-run by hand
at any time to re-apply or audit:

```powershell
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\link_ping_prometheus'
$a = Get-Acl $k
$a.SetSecurityDescriptorSddlForm('D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;;KA;;;SY)(A;;KA;;;BA)')
Set-Acl -Path $k -AclObject $a
```

Both ACE pairs name the principals by SID (`S-1-5-18` = SYSTEM, `S-1-5-32-544` =
Administrators) instead of by account name: the names are localized on
non-English Windows ("Administratoren" on a German install) and would not
resolve, so the ACL step would fail on a host that is otherwise fine.

## Security notes

- LocalSystem is the default account; pass `SERVICE_ACCOUNT` (e.g.
  `NT AUTHORITY\LocalService` or a gMSA) for least privilege.
- Arguments are snapshotted at install time: changing runtime flags requires
  uninstall/reinstall.
- Credentials in the `Environment` value are plaintext and readable by
  administrators; restrict who counts as an administrator on the node.

See the [Windows service guide](../../docs/windows-service.md) for full detail.
