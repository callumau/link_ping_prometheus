# Ansible deployment

Deploys the pre-built `link_ping_prometheus` binary and its service
definition to remote Linux (systemd) and Windows (SCM) hosts.

## Prerequisites

- Ansible on the control node (2.15+); `pip install pywinrm` for the
  Windows play.
- Built binaries copied here under these exact names (release tags
  from GHCR work too, but the playbooks copy plain files):
  - `files/link_ping_prometheus-linux-amd64`
  - `files/link_ping_prometheus-windows-amd64.exe`
  From `./dev_build.sh` the names differ — the build writes
  `build/link_ping_prometheus` and `build/link_ping_prometheus.exe`,
  so copy them across:

  ```sh
  cp build/link_ping_prometheus \
     deploy/ansible/files/link_ping_prometheus-linux-amd64
  cp build/link_ping_prometheus.exe \
     deploy/ansible/files/link_ping_prometheus-windows-amd64.exe
  ```

  Goreleaser emits archives instead
  (`dist/link_ping_prometheus_Linux_x86_64.tar.gz`,
  `dist/link_ping_prometheus_Windows_x86_64.zip`, see
  `.goreleaser.yaml`), so unpack and rename the binary inside:

  ```sh
  tar -xzf dist/link_ping_prometheus_Linux_x86_64.tar.gz \
    -C /tmp link_ping_prometheus
  mv /tmp/link_ping_prometheus \
     deploy/ansible/files/link_ping_prometheus-linux-amd64
  unzip -o dist/link_ping_prometheus_Windows_x86_64.zip \
    link_ping_prometheus.exe -d /tmp/win
  mv /tmp/win/link_ping_prometheus.exe \
     deploy/ansible/files/link_ping_prometheus-windows-amd64.exe
  ```

  (`goreleaser release` / `--snapshot` write those archives into
  `dist/`, and the GitHub release assets carry the same names — unpack
  and rename them the same way. `dev_build.sh` tags the binary with a
  build timestamp; goreleaser sets `main.version` from the git tag.)

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
- **Windows:** writes `targets.json` to the install directory and
  appends `-targets=<install dir>\targets.json` to the options when
  `link_ping_targets_json` is set — a client/both service installed
  without `-targets` exits 1 (`no targets specified`) and the SCM
  restart ladder crash-loops it every 5s. It then copies the binary,
  creates the service by running
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
  does not rewrite `binPath` for an existing service. That applies to
  `-targets` as well: setting `link_ping_targets_json` on a host whose
  service already exists rewrites `targets.json` but needs a reinstall
  before the service picks the path up. The file's *content* is rewritten
  on every run, so editing targets on an already-installed host takes
  effect on the next restart (or SIGHUP/reload on Linux).

## Secrets

`link_ping_echo_secret`, `link_ping_echo_secret_old`,
`link_ping_metrics_user`, and `link_ping_metrics_pass` are delivered
through the service environment (EnvironmentFile on Linux, SCM
Environment registry key on Windows), never as service arguments —
matching the credential-handling rules in the README's Security
section. Encrypt the vars file with ansible-vault.

**Debugging hidden output:** the three secret-bearing tasks (rendering the
credential lines, writing the env file, and the Windows registry entries)
are marked `no_log: true` so credentials never reach task output or a
`--diff` transcript. A failure in one of them is therefore reported only
as "output has been hidden due to no_log"; re-run that one host once with
`ANSIBLE_NO_LOG=false` (and no `--diff`) to see the real error, then drop
the override.

**Windows caveat:**
`HKLM\SYSTEM\CurrentControlSet\Services\<service>\Environment` is
readable by all local users, so values placed there are only as private
as interactive logon on the host. The batch installer
(`installer/windows/install-service.bat`) uses the SAME registry key and
prompts for the values so they stay off the command line — it does not
ACL them either (only its log directory is ACL'd). Where a secret has to
be protected rather than merely kept off the command line, use a
dedicated service account and restrict logon instead of this play.

**Linux caveat:** `/etc/link_ping_prometheus.env` holds both `OPTIONS`
and the credential env vars under mode 0600, and is rewritten (with a
service restart) whenever its content changes.

**Changing flags on an existing host:** the service command line
(`binPath`, which snapshots the flags at install time) is not rewritten
on a re-run — that needs a reinstall (uninstall + install). Credential
changes ARE applied on a re-run: the environment key is rewritten and
the play restarts the service when it changed.

**Install path:** the Linux play installs to `link_ping_install_dir`,
but the shipped systemd unit hardcodes
`/usr/local/bin/link_ping_prometheus`. Changing that variable also
requires editing `ExecStart` in the unit (or dropping a unit override).
