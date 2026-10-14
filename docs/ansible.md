# Deployment (Ansible)

For fleets, `deploy/ansible/playbook.yml` deploys the pre-built binary
and service definition to remote Linux (systemd, using
`installer/linux/link_ping_prometheus.service` — the hardened unit, driven
by `/etc/link_ping_prometheus.env`) and Windows (SCM via `sc.exe`, with the
same failure-recovery ladder as `main.go`) hosts. Secrets are delivered via
the service environment on both platforms — never service arguments, and
the secret-bearing tasks are marked `no_log` so they cannot leak into
`-v`/`--diff` output. See `deploy/ansible/README.md` for prerequisites and
usage.

For a multi-site mesh — one identical targets file on every site, the
allowlist derived from it (`-allow-from-targets`), and an unattended
config-repo pull — see [Mesh deployment](mesh-deployment.md) and
`deploy/ansible/mesh.yml`.
