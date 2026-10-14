# Targets File

JSON file with an array of `{"name": "...", "address": "host:port"}` objects. Optional per-target `interval`/`timeout` override the global `-interval`/`-timeout` (duration strings like `"500ms"`, `"1s"`; 0 or absent means use global):

```json
[
  {"name": "server1", "address": "192.168.1.10:4000"},
  {"name": "server2", "address": "192.168.1.11:4000", "interval": "200ms", "timeout": "800ms"}
]
```

Max 1000 targets, max file size 1 MB. Per-target interval/timeout must be >0 when set; `interval >= timeout` warns (global and per-target) and `reconnect-interval < interval` is an error.

**Address syntax:** `address` is `host:port` with the port in 1-65535, checked syntactically at load time (no DNS lookup, so a reload never depends on the network). Two dialable forms go beyond plain RFC 1123 name labels: a DNS name may carry one trailing dot for the FQDN root (`mon.example.com.:5000`), and an IPv6 literal may carry a `%zone` scope suffix whose characters are letters, digits, `_`, `-` and `.` so VLAN interface names work (`[fe80::1%eth0.100]:5000`). A zone on a DNS name or an IPv4 literal is rejected (`example.com%eth0:80`, `1.2.3.4%eth0:80`), and so is a trailing dot on an IP literal (`1.2.3.4.:80`) — the root dot is only stripped from names.

**Hot reload:** send `SIGHUP` to re-read the file without a restart (Unix), or run with `-targets-reload-interval` (e.g. `30s`) for automatic polling — the only option under a Windows service, which has no SIGHUP. On reload: new targets start probing, removed targets stop and their series are deleted from `/metrics` (Prometheus marks the vanished series stale, so `link_up`-keyed alerts stop firing for them — an `absent()`/`up` alert covers a fully dead client), and targets whose address/intervals changed restart with the new values. A file that is mid-edit or invalid keeps the previous set running — reload failures are logged at Error level, never fatal. A reload whose file parses to an empty array logs a warning that all probing has stopped. A probe loop that fails to join within 5s is left stopped (its socket may still be draining) and its series are purged once it does exit, so a stuck loop cannot leave a frozen `link_up=1` behind.

**One file for a whole mesh:** run every site with `-mode=both -allow-from-targets` and deploy the *same* `targets.json` — listing every site, including the local one — on each of them; only `-source` differs per host. The agent drops the entry whose `name` matches its own `-source` (exact match) and derives its fail-closed allowlist from the remaining target addresses, so there is no per-site allowlist to maintain and adding a site is a one-line edit to one shared file. Addresses must be IP literals in this mode. See [Mesh deployment](mesh-deployment.md) for the full runbook, the GitHub config-repo pull, and the Ansible playbook (`../deploy/ansible/mesh.yml`).
