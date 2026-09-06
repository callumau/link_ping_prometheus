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
  shipped hardened systemd unit (`installer/linux/`), renders CLI flags
  into `OPTIONS` inside `/etc/link_ping_prometheus.env` (0600), writes
  `targets.json` when `link_ping_targets_json` is set, then enables and
  starts the service.
- **Windows:** copies the binary, creates the service with
  `sc.exe` (auto start), applies the same failure-recovery ladder as
  `main.go` (`sc.exe failure ... restart/5000`), delivers secrets via
  the SCM `Environment` registry key (never the command line), opens
  UDP 4000 in the firewall for server/both mode, and starts the
  service only if it is not already running.

## Secrets

`link_ping_echo_secret`, `link_ping_echo_secret_old`,
`link_ping_metrics_user`, and `link_ping_metrics_pass` are delivered
through the service environment (EnvironmentFile on Linux, SCM
Environment registry key on Windows), never as service arguments —
matching the credential-handling rules in the README's Security
section. Encrypt the vars file with ansible-vault.
