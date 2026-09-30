# Windows service installer

Batch scripts to install/uninstall `link_ping_prometheus.exe` as a hardened
Windows service. Run from an **elevated** prompt, with the `.exe` in this
folder (or edit `EXE_PATH` at the top of the script).

| Script | Purpose |
| --- | --- |
| `install-service.bat` | Fresh install, or in-place upgrade when a newer binary is provided |
| `uninstall-service.bat` | Stop, remove service + event-log source + credential env vars |

## What install-service.bat does

1. Verifies admin rights and binary presence
2. Copies the binary into `%ProgramFiles%\link_ping_prometheus` (Admins-only-write location; weak binary-path ACLs are the classic Windows service-persistence attack)
3. Creates an ACL-hardened log directory (`C:\ProgramData\link_ping_prometheus\logs`)
4. Installs via `-svc=install`, which bakes in:
   - SCM recovery: restart on failure after 5s
   - Delayed auto-start; dependencies on `Tcpip` and `W32Time`
   - Event Log source (`Application` → `link_ping_prometheus`) for lifecycle/fatal events
   - Credentials are never persisted into the service config
5. Post-install hardening:
   - Escalating restart ladder: 5s → 30s → 60s, failure counter resets daily
   - Per-service SID (`sc sidtype unrestricted`) granted write access only to the log directory
6. Prompts for optional credential environment variables
   (`LINK_PING_METRICS_USER/PASS`, `LINK_PING_ECHO_SECRET`) — Enter skips.
7. Restricts the ACL on the credential registry key (see below)
8. Starts the service and prints its state

**Re-running the installer on an existing installation performs an in-place
upgrade**: the new binary is SHA256-compared against the installed one —
identical is a no-op, different stops the service, swaps only the binary,
and restarts. All existing parameters are kept untouched (they are
snapshotted at fresh-install time; flag changes require uninstall/reinstall).

Edit the VARIABLES section at the top for binary/install paths; everything
else is asked interactively: mode (server/client/both), metrics address,
targets — a JSON file or a single host:port endpoint — the required client
IP allow-list for server/both, log directory, optional service account,
and a summary/confirm step before anything is installed.

## Credential storage and the `Environment` key

The credential flags are deliberately stripped from the persisted service
config, so the per-service `Environment` key

```text
HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment
```

is the only delivery path for the echo HMAC secret and the metrics Basic-auth
password. Windows gives that key an inherited ACL that lets **every local
user** read it.

`install-service.bat` therefore drops inheritance and re-grants access
explicitly whenever a credential was entered:

- `SYSTEM` — full control
- `BUILTIN\Administrators` — full control
- no per-service SID grant: the service process never reads this key, the SCM
  reads it as LocalSystem and injects the values into the service environment,
  so a custom service account is unaffected

The step fails loudly — if the ACL cannot be set the installer prints an
`ERROR` line and exits non-zero rather than leaving a world-readable key
behind. On success it echoes
`Environment key ACL restricted to SYSTEM + BUILTIN\Administrators.`

A non-administrator querying the key (for example
`reg query HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment`)
gets **access denied**, and `Get-Acl` shows only the two entries above with
inheritance disabled. Administrators still read the plaintext values, which
includes every account that can take the machine over.

**Rotation.** The values in that key are plaintext: anything that could read
the key before the ACL step (or while the ACL was still inherited) can still
use the secret. Treat the secret as compromised and rotate it — the
zero-downtime rotation runbook (new secret + previous secret in the service
environment, then drop the old one) is in the main README's *Security*
section; the wizard's own "previous, for rotation" prompt writes
`LINK_PING_ECHO_SECRET_OLD` for exactly that runbook. Rotate the metrics
password by replacing the value and restarting the service.

**Sites that manage registry ACLs by policy.** The installer's PowerShell
snippet is exactly what a GPO-driven equivalent should apply, and it can be
re-run by hand at any time to re-apply or audit the ACL:

```powershell
powershell -NoProfile -Command "$k='HKLM:\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment'; $a=Get-Acl $k; $a.SetAccessRuleProtection($true,$false); foreach($n in 'SYSTEM','BUILTIN\Administrators'){ $a.AddAccessRule((New-Object System.Security.AccessControl.RegistrySystemAccessRule($n,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))) }; Set-Acl -Path $k -AclObject $a"
```

`icacls` is the equivalent for sites that standardize on it:

```bat
icacls "HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment" /inheritance:r /grant "SYSTEM:(F)" "Administrators:(F)"
```

## Security notes

- LocalSystem is the default account; pass `SERVICE_ACCOUNT` (e.g.
  `NT AUTHORITY\LocalService` or a gMSA) for least privilege.
- Arguments are snapshotted at install time: changing runtime flags requires
  uninstall/reinstall.
- Credentials in the `Environment` key are plaintext and readable by
  administrators; restrict who counts as an administrator on the node.

See the README's *Windows* section under Installation for full detail.
