# Ansible deployment

Deploys the pre-built `link_ping_prometheus` binary and its service
definition to remote Linux (systemd) and Windows (SCM) hosts.

## Prerequisites

- Ansible on the control node (2.15+); `pip install pywinrm` for the
  Windows play. The WinRM certificate check stays on, so the control
  node also needs your internal CA bundle (see WinRM certificate
  validation below).
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

- **Both plays:** refuse to install when the metrics listener is exposed
  unauthenticated (see Pre-flight guardrail below).
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
  `Environment` registry key (never the command line) and then ACLs that
  key to SYSTEM/Administrators too, opens UDP 4000
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

## Pre-flight guardrail

`-metrics` is the management plane: `/metrics` **and** `/status` carry
the whole probe topology (target addresses, packet counts, build info). A
wildcard bind with no credentials and no TLS publishes all of it to every
host that can route to the box, so both plays assert before the first
install task and stop with an explicit message when all three hold:

- `link_ping_metrics_listen` binds a wildcard — `0.0.0.0:2112`, `:2112`
  (empty host), or an IPv6 wildcard such as `[::]:2112`. `127.0.0.1:2112`
  and `localhost:2112` are **not** wildcards; the shipped default is the
  loopback, so the normal deployment passes.
- neither `link_ping_metrics_user` nor `link_ping_metrics_pass` is set
  (the binary refuses a half-configured pair, so one empty var means auth
  is off), and
- `link_ping_extra_args` carries no `-metrics-tls-cert`/`-metrics-tls-key`
  and no `-metrics-allow-insecure`.

If any one of them is not true the assert passes **silently**, so the
localhost default adds no noise to a run.

### Overriding it deliberately

The guardrail has no bypass switch on purpose: making it pass means
adding one of the four controls it names, not silencing the check.

1. **Bind the loopback and scrape through a tunnel/agent.** Keep
   `link_ping_metrics_listen: "127.0.0.1:2112"` and reach it from
   Prometheus with an SSH/WinRM port forward, `socat`, or a node exporter
   running on the monitored host. The listener never leaves the box, and
   the transport to Prometheus is whatever your tunnel makes it.
2. **Set credentials.** Fill in `link_ping_metrics_user` and
   `link_ping_metrics_pass`; they are delivered through the service
   environment, never the command line. Note the binary then refuses to
   start unless TLS or `-metrics-allow-insecure` is present too — pair
   this with remedy 3.
3. **Add TLS.** Pass `-metrics-tls-cert` and `-metrics-tls-key` (both,
   or neither) in `link_ping_extra_args`. `-metrics-allow-insecure`
   instead keeps plaintext HTTP with Basic auth — better than no auth,
   but the credentials are only base64 on the wire.
4. **Firewall TCP 2112 to the monitoring hosts only.** The play does not
   open or close TCP 2112 (it opens UDP 4000 in the Windows firewall for
   server/both mode), and it cannot verify your firewall, so add the rule
   in your own play/infrastructure code before the run — Linux `ufw` /
   `firewalld`, Windows `netsh advfirewall firewall add rule`. With no
   credentials, the firewall is the only thing between the network and
   `/status`.

## WinRM certificate validation

`ansible_winrm_server_cert_validation: validate` is the shipped posture
and `inventory.example.yml` keeps it: the WinRM channel carries the
service credentials (HMAC secret, metrics password), so an unverified
peer means an unauthenticated control node can read and rewrite them.
The example also sets `ansible_winrm_ca_bundle_path` — point it at the
PEM bundle of your internal CA (root plus intermediates, concatenated),
copied to the **control node** (the path is read there, not on the
managed Windows host):

```sh
# control node, once per CA
cat internal-root-ca.pem issuing-ca.pem \
    > /etc/ansible/ca-bundle.pem
```

A Windows control node uses the same setting with a `C:\...` path. If
the WinRM certificate comes from a public CA, drop
`ansible_winrm_ca_bundle_path` entirely and let pywinrm use the control
node's trust store. Never set the validation to `ignore` in production —
it turns the check that the peer is who it claims to be off, on the one
channel that delivers the secrets.

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
readable by all local users by default, so values placed there would
only be as private as interactive logon on the host. The play drops the
key's inherited ACEs and keeps SYSTEM + BUILTIN\Administrators full
control after writing the values — the same rule, and the same
PowerShell calls, the batch installer
(`installer/windows/install-service.bat`) applies — so a local user can
no longer read the metrics password or the HMAC secret out of the
registry. The SCM builds the service's environment block as SYSTEM, so
the service process does not need its own read access to the key. Two
consequences to keep in mind: a binary started **interactively** (not as
the service) gets none of these variables and therefore starts with
metrics auth off, and the values are not secret-grade against an
administrator or a SYSTEM-level compromise. Where a secret has to be
protected rather than merely kept off the command line, use a dedicated
service account and restrict logon on the host.

**Linux caveat:** `/etc/link_ping_prometheus.env` holds both `OPTIONS`
and the credential env vars under mode 0600, and is rewritten (with a
service restart) whenever its content changes.

**Credential rotation:** set `link_ping_echo_secret` to the new value
and `link_ping_echo_secret_old` to the one being retired (leave
`link_ping_echo_secret_old` empty once the fleet has converged), then
follow the zero-downtime rotation runbook in the main README
("Secret rotation without an outage", Security section) — servers first
with both secrets, then the clients, then drop the old one. This play
delivers both values through the service environment and notifies the
restart handler only when a value actually changed, so a rotation is
applied by the re-run; the ordering, and the
`link_server_probes_dropped_total{reason="hmac"}` signal that shows a
half-rotated fleet, are the runbook's job, not the play's.

**Changing flags on an existing host:** the service command line
(`binPath`, which snapshots the flags at install time) is not rewritten
on a re-run — that needs a reinstall (uninstall + install). Credential
changes ARE applied on a re-run: the environment key is rewritten and
the play restarts the service when it changed.

**Install path:** the Linux play installs to `link_ping_install_dir`,
but the shipped systemd unit hardcodes
`/usr/local/bin/link_ping_prometheus`. Changing that variable also
requires editing `ExecStart` in the unit (or dropping a unit override).
