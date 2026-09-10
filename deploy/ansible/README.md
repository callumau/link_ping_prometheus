# Ansible deployment

Deploys the pre-built `link_ping_prometheus` binary and its service
definition to remote Linux (systemd) and Windows (SCM) hosts.

## Prerequisites

- Ansible on the control node (2.15+); `pip install pywinrm` for the
  Windows play.
- Built binaries copied here (release tags from GHCR work too, but the
  playbooks copy plain files):
  - `files/link_ping_prometheus-linux-amd64`
  - `files/link_ping_prometheus-windows-amd64.exe`
  Build with `./dev_build.sh` or goreleaser, then copy from `build/`.

## Usage

```sh
cp group_vars/all.example.yml group_vars/all.yml   # then edit
cp inventory.example.yml inventory.yml             # then edit
ansible-vault encrypt group_vars/all.yml           # when carrying secrets
ansible-playbook -i inventory.yml playbook.yml --ask-vault-pass
```

## What it does

- **Linux:** installs the binary to `/usr/local/bin`, writes the
  shipped hardened systemd unit (`installer/linux/`), writes
  `/etc/link_ping_prometheus.env` (0600) containing the rendered CLI
  flags as `OPTIONS=...` plus any credential env vars, writes
  `targets.json` when `link_ping_targets_json` is set, then enables and
  starts the service. The file is always written — the unit expands
  `$OPTIONS`, so an absent file would start the binary on fail-closed
  defaults and crash-loop it.
- **Windows:** copies the binary, creates the service by running
  `link_ping_prometheus.exe <options> -svc=install` — the only path that
  applies the hardened SCM config from `main.go` (`DelayedAutoStart`
  plus the load-bearing Tcpip/W32Time dependencies and the OnFailure
  restart ladder) — ACLs `C:\ProgramData\link_ping_prometheus\logs` to
  SYSTEM/Administrators and passes `-log-file=...\service.log` (stdout
  is discarded under the SCM), delivers secrets via the SCM
  `Environment` registry key (never the command line), opens UDP 4000
  in the firewall for server/both mode, and starts the service only if
  it is not already running. The `sc.exe failure` ladder is restated
  afterwards; it is idempotent and only makes the baked-in values
  explicit. The play also re-applies `DelayedAutoStart` and the
  Tcpip/W32Time dependencies with `sc.exe config`, so a service that was
  created by an older play is hardened too. Note that `-svc=install`
  snapshots the flags into the service `binPath`: changing options on an
  existing service requires a reinstall (uninstall + install) — the play
  does not rewrite `binPath` for an existing service.

## Secrets

`link_ping_echo_secret`, `link_ping_echo_secret_old`,
`link_ping_metrics_user`, and `link_ping_metrics_pass` are delivered
through the service environment (EnvironmentFile on Linux, SCM
Environment registry key on Windows), never as service arguments —
matching the credential-handling rules in the README's Security
section. Encrypt the vars file with ansible-vault.

**Windows caveat:**
`HKLM\SYSTEM\CurrentControlSet\Services\<service>\Environment` is
readable by all local users, so values placed there are only as private
as interactive logon on the host. Where a secret has to be protected
rather than merely kept off the command line, use the batch installer's
ACL'd delivery (`installer/windows/install-service.bat`, which prompts
for the values and documents the same caveat) or a dedicated service
account instead of this play.

**Linux caveat:** `/etc/link_ping_prometheus.env` holds both `OPTIONS`
and the credential env vars under mode 0600, and is rewritten (with a
service restart) whenever its content changes.
