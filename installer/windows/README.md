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
7. Starts the service and prints its state

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

## Security notes

- The per-service `Environment` registry key used for credentials is readable
  by all local users by default — treat values as non-secret-grade or restrict
  interactive logon on the host.
- LocalSystem is the default account; pass `SERVICE_ACCOUNT` (e.g.
  `NT AUTHORITY\LocalService` or a gMSA) for least privilege.
- Arguments are snapshotted at install time: changing runtime flags requires
  uninstall/reinstall.

See the README's *Windows* section under Installation for full detail.
