# Organisation mesh deployment

Run this UDP link monitor as a full mesh: every site probes every other,
measuring all N×(N−1) directional paths rather than one star around a hub.

Reference: [Flags](../README.md#flags), [Targets
File](../README.md#targets-file), [operations and
tuning](operations.md), [scraping](scraping.md).

## Concept

The agent derives three things from one file:

1. **One shared `targets.json`, deployed everywhere** — every site as
   `{"name", "address"}`, including the local one. A site's `name` is also
   its `-source`, hence its `source` label.
2. **A per-site `-source`**, the only value differing between hosts.
3. **A derived, fail-closed allowlist** (`-allow-from-targets`) from those
   addresses, which must be IP literals (config load never resolves DNS).
   `-allow` adds extra CIDRs or non-mesh hosts.

The agent skips the target matching its own `-source`, leaving remote peers;
adding or changing a site is one edit, picked up on
`-targets-reload-interval` or SIGHUP (see
[Reload semantics](#reload-semantics-what-refreshes-and-what-does-not)).

## Worked example: 10 sites

### Sites

Addresses are from the RFC 5737 ranges. Each site echoes on UDP 4000 and is
listed by the name it uses as `-source`.

| Site (`-source` = targets `name`) | Echo address (`ip:4000`) |
| --- | --- |
| `site01` | `192.0.2.11:4000` |
| `site02` | `192.0.2.12:4000` |
| `site03` | `192.0.2.13:4000` |
| `site04` | `198.51.100.21:4000` |
| `site05` | `198.51.100.22:4000` |
| `site06` | `198.51.100.23:4000` |
| `site07` | `203.0.113.31:4000` |
| `site08` | `203.0.113.32:4000` |
| `site09` | `203.0.113.33:4000` |
| `site10` | `203.0.113.34:4000` |

The port is part of the `address` and must match the site's `-listen`
(default `:4000`). For several addresses, list the site once per address
with distinct `name`s.

### The shared `targets.json`

Deploy it to all 10 sites; every allowlist is derived from it.

```json
[
  {"name": "site01", "address": "192.0.2.11:4000"},
  {"name": "site02", "address": "192.0.2.12:4000"},
  {"name": "site03", "address": "192.0.2.13:4000"},
  {"name": "site04", "address": "198.51.100.21:4000"},
  {"name": "site05", "address": "198.51.100.22:4000"},
  {"name": "site06", "address": "198.51.100.23:4000"},
  {"name": "site07", "address": "203.0.113.31:4000"},
  {"name": "site08", "address": "203.0.113.32:4000"},
  {"name": "site09", "address": "203.0.113.33:4000"},
  {"name": "site10", "address": "203.0.113.34:4000"}
]
```

Option A renders it from `link_ping_mesh_peers` with `to_nice_json`
(4-space indent, keys sorted), so the bytes are identical per host and the
task stays idempotent and `--check --diff` quiet. Per-target
`interval`/`timeout` overrides from the
[targets file](targets-file.md) guide work here too.

**`address` must be an IP literal**, or `-allow-from-targets` cannot derive
an entry (config load never resolves DNS) and the agent exits:

```text
ERROR msg="Program exited with error" err="target \"site02\"
address \"peer.example.com:4000\" is not an IP literal ...
-allow-from-targets cannot allowlist a DNS name (config load never
resolves); use IP addresses in the mesh targets file, or list the host
in -allow"
```

A host with no static address can still be a site: give its numeric address
here and add the name to `-allow`; the play asserts the same rule.

### Linux flags (systemd)

The shipped unit runs `link_ping_prometheus $OPTIONS` and reads
`/etc/link_ping_prometheus.env` (mode 0600). On `site01`:

```sh
# /etc/link_ping_prometheus.env  (mode 0600)
OPTIONS="-mode=both -source=site01 -listen=:4000 -metrics=127.0.0.1:2112 -targets=/etc/link_ping_prometheus/targets.json -allow-from-targets -targets-reload-interval=30s"
# Secrets are environment variables, never CLI flags: flags are visible in
# `ps` to every local user. Same file, still 0600.
LINK_PING_ECHO_SECRET=<shared-secret>
```

- `-mode=both`, not `server`: a mesh site must echo and probe; `server`
  cannot derive an allowlist.
- `-source=site01` is the only per-site value.
- `-targets-reload-interval=30s` applies new peers without a restart; on
  Unix `systemctl reload link_ping_prometheus` (SIGHUP) also works.
- `-metrics` is listed for clarity; `127.0.0.1:2112` is the default.
- `-allow` is absent because the allowlist is derived; add it only for
  extra CIDRs or non-mesh hosts.

Install the unit per the [Linux (systemd)](linux-systemd.md) guide, or use
the Ansible playbook below.

### Windows service install

`-svc=install` snapshots the runtime flags into the service `binPath`, so
the install line *is* the config. On `site01`, from an elevated prompt:

```powershell
$exe = 'C:\Program Files\LinkPing\link_ping_prometheus.exe'
& $exe -mode=both -source=site01 -listen=:4000 -metrics=127.0.0.1:2112 `
  -targets="C:\Program Files\LinkPing\targets.json" `
  -allow-from-targets -targets-reload-interval=30s `
  -log-file="C:\ProgramData\link_ping_prometheus\logs\service.log" `
  -svc=install
```

`-svc=install` validates the flags before it writes the SCM entry and refuses a
config the agent would reject at startup (unknown `-mode`, `-echo-secret-old`
without `-echo-secret`, a metrics auth/TLS pair that is half-set or will not
load, server/both mode with an empty allowlist), so a failed install is the
configuration talking, not the SCM. A missing `-targets-reload-interval` is
only a warning — but on a service that file is then read once and never again.

Two load-bearing warnings:

- `-log-file` is required: stdout is discarded under the SCM. The agent
  enforces the file's DACL (SYSTEM, Administrators, service account) at
  startup.
- `-echo-secret` is not persisted and would show on a command line; deliver
  it via the service environment, then restrict that key's ACL (see the
  [Windows service guide](windows-service.md)):

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment" `
  /v LINK_PING_ECHO_SECRET /t REG_SZ /d "<shared-secret>" /f
```

- `-targets-reload-interval` is mandatory: a service has no SIGHUP.
- Path flags (`-targets`, `-log-file`, `-metrics-tls-*`) are rewritten to
  absolute paths at install; the SCM's working directory is unrelated.

## Directionality: A→B and B→A are not the same measurement

A probe from A to B measures A→B forward plus B→A return; the reverse probe
measures B→A forward plus A→B return — the same legs with per-direction
queueing, policy routing and NAT/conntrack reversed. On an asymmetric path
the readings differ substantially; neither is redundant.

| Measurement | Exported by | Series |
| --- | --- | --- |
| A→B | **A's** agent | `link_up{source="siteA", target="siteB", address="<B>:4000"}` |
| B→A | **B's** agent | `link_up{source="siteB", target="siteA", address="<A>:4000"}` |

`source` is the local site, `target` the remote, `address` the remote
`ip:port`, part of the series identity: an IP change withdraws the old
series on reload (see [Renumbering a site](#renumbering-a-site)). RTT is
client-side monotonic, so only the HMAC replay window needs clock agreement
(see [Prerequisites](#prerequisites)).

### Grafana dashboard on a mesh

The bundled [dashboard](../grafana-dashboard.json) has three
`label_values(...)` variables on `link_up`:

| Variable | Query | Selection | Mesh use |
| --- | --- | --- | --- |
| `source` | `label_values(link_up,source)` | multi-select, `All` | the local site(s) |
| `target` | `label_values(link_up,target)` | multi-select, `All`, custom values allowed | the remote site(s) |
| `instance` | `label_values(link_up,instance)` | **single-select, no `All`** | the scrape endpoint |

Every per-link panel filters on all three
(`link_up{instance=~"$instance", target=~"$target", source=~"$source"}`), so
`source=site01, target=site04` is exactly that direction. `instance` is
single-select with no `All`, and names the scrape endpoint: under the
per-site scraper every agent is `localhost:2112`, so `source`/`target`
select the mesh; a per-address scrape makes `instance` per-site and pins the
dashboard to one agent — keep the per-site pattern, or add `includeAll` and
a regex.

Useful queries (numerator and denominator windows must match):

```promql
# One direction, both ends:
link_up{source="site01", target="site04"}

# Loss for every direction at once:
100 * sum by (source, target) (rate(link_probes_timed_out_total[5m]))
    / sum by (source, target) (rate(link_probes_sent_total[5m]))

# Directional skew: the two readings of the same pair, side by side:
link_rtt_srtt_seconds{source="site01", target="site04"}
or link_rtt_srtt_seconds{source="site04", target="site01"}
```

## Always set `-echo-secret` on every node

`-echo-secret` (env `LINK_PING_ECHO_SECRET`) authenticates the probe with
HMAC-SHA256 and grows the frame from 24 to 32 bytes. The example lists
addresses only, so set it on every node. A mesh with no `-echo-secret` has
**only** the derived exact-IP allowlist as reflector protection, so a secret
is strongly recommended. A half-configured pairing **still reads healthy**:

- A server without it accepts the client's 32-byte HMAC frame as a payload
  probe and echoes it: the client sees a fine link, no `hmac` drop reason,
  `link_up=1`.
- Only `link_server_unauth_hmac_frames_total{source}` shows the shape,
  alerted by `LinkMonitorReflectorUnauthenticated` in
  `rules/link-monitor.yml` — load it everywhere. A secret-less 24-byte
  header plus exactly 8 bytes of payload has the same shape.

The allowlist is fail-closed (rejects a source before any crypto or metric
work), and HMAC makes each entry meaningful:

- Without HMAC, anyone who can spoof an allowlisted source can reflect
  probes 1:1 — the echo is never larger than the probe, so a reflector but
  not an amplifier.
- A CIDR in `-allow` lets an authenticated source spend the dynamic series
  slots (see [Growth
  headroom](#growth-headroom-and-the-256-entry-cap)); HMAC stops a spoofer
  from evicting real peers.

Never rotate by editing only some sites; read the [Security](security.md)
rotation runbook first.

## Config distribution

Two paths; pick one. If both run, the pull overwrites what Ansible pushed.

### Option A: Ansible push (`deploy/ansible/mesh.yml`)

One group var, shared by every host, writes the identical `targets.json`
byte for byte on each site:

```yaml
# group_vars/mesh.yml
link_ping_mesh_peers:
  - {name: site01, address: "192.0.2.11:4000"}
  - {name: site02, address: "192.0.2.12:4000"}
  # ... all 10 sites, including the one you are deploying
```

Each host's own site comes from the `link_ping_site` host var or
`inventory_hostname`, and must equal one of the `name`s in
`link_ping_mesh_peers`. The play asserts it — the self-skip is an exact
match, so a typo would make a site probe itself and export a loopback RTT.
The inventory:

```yaml
all:
  children:
    link_ping_mesh_linux:
      hosts:
        site01:
          ansible_host: 192.0.2.11
          link_ping_site: site01
        site04:
          ansible_host: 198.51.100.21
          link_ping_site: site04
    link_ping_mesh_windows:
      hosts:
        site07:
          ansible_host: 203.0.113.31
          link_ping_site: site07
          ansible_connection: winrm
          ansible_winrm_server_cert_validation: validate
          ansible_winrm_ca_bundle_path: /etc/ansible/ca-bundle.pem
```

Then:

```sh
cp group_vars/mesh.example.yml group_vars/mesh.yml   # then edit
cp inventory.example.yml inventory.yml               # then edit
ansible-vault encrypt group_vars/mesh.yml            # carries the secret
ansible-playbook -i inventory.yml mesh.yml --ask-vault-pass
```

The play mirrors `deploy/ansible/playbook.yml` for non-mesh work: binary
install, hardened systemd unit, `/etc/link_ping_prometheus.env`, Windows
`-svc=install`, `sc.exe` hardening, log-dir ACL, SCM `Environment` secret
delivery, UDP 4000 firewall, restart-on-change handlers. See
[deploy/ansible/README.md](../deploy/ansible/README.md) for prerequisites,
guardrails, WinRM CA pinning, secret handling.

Mesh-specific parts: the shared file, `-allow-from-targets` (and its
self-skip), the reload interval, and the identity assertions.

### Option B: unattended pull from a GitHub repo

For fleets without a configuration-management control plane, or when the
network owner should edit the topology: keep `targets.json` in a dedicated
git repo and pull it on a schedule with a **read-only deploy key**.

`deploy/mesh/pull-config.sh` (Linux) and `deploy/mesh/pull-config.ps1`
(Windows) both:

1. Clone shallowly, then `fetch` + `reset --hard`; git never writes the
   live file.
2. Validate the pulled file as JSON **before** touching the live file; a
   parse failure exits non-zero and leaves the previous file.
3. Install atomically (copy to a temp file, `rename`/`mv` over the live
   path).
4. Serialise runs with a lock.
5. Log to stderr and syslog/Event Log; never print the key.

#### Repo and key hygiene

- **No secrets in the config repo** — topology only. The HMAC secret and
  metrics credentials come from the service environment (Ansible) or the
  SCM `Environment` key / `EnvironmentFile` (manual).
- Use a dedicated **deploy key** with read-only access to that one repo
  (GitHub: Settings → Deploy keys, leave "Allow write access" unchecked); a
  write-capable key would let anyone reaching a monitored site author the
  fleet's topology.
- Pin the server key with a `known_hosts` file. Both scripts run ssh with
  `StrictHostKeyChecking=yes`, an explicit `UserKnownHostsFile`, and
  `IdentitiesOnly=yes`, refusing an unpinned key rather than trusting it on
  first use.
- The private key must be mode `0600` (Linux) or unreadable by broad local
  principals (Windows DACL); both scripts refuse an exposed key, failing
  early instead of a bare `Permission denied (publickey)`.

##### Linux install

```sh
# 1. Script and its settings.
sudo install -m 0755 deploy/mesh/pull-config.sh \
  /usr/local/bin/link_ping_pull_config
sudo install -d -m 0700 /etc/link_ping_pull_config

# 2. Deploy key (read-only, no passphrase), mode 0600.
sudo install -m 0600 /path/to/mesh-config-deploy-key \
  /etc/link_ping_pull_config/deploy_key
ssh-keyscan -t rsa,ecdsa,ed25519 github.com > /tmp/kh   # then VERIFY the
# fingerprints against GitHub's published ones before installing:
sudo install -m 0644 /tmp/kh /etc/link_ping_pull_config/known_hosts

# 3. Settings file (paths and repo URL only — no secret).
sudo tee /etc/link_ping_pull_config.env >/dev/null <<'EOF'
LINK_PING_CONFIG_REPO=git@github.com:org/mesh-config.git
LINK_PING_CONFIG_BRANCH=main
LINK_PING_CONFIG_WORK=/var/lib/link_ping_pull_config/repo
LINK_PING_CONFIG_DEST=/etc/link_ping_prometheus
LINK_PING_CONFIG_KEY=/etc/link_ping_pull_config/deploy_key
LINK_PING_CONFIG_KNOWN_HOSTS=/etc/link_ping_pull_config/known_hosts
LINK_PING_CONFIG_FILE=targets.json
EOF
sudo chmod 0644 /etc/link_ping_pull_config.env

# 4. First run, by hand, before trusting the timer.
sudo /usr/local/bin/link_ping_pull_config

# 5. Units. The service is a oneshot; the timer schedules it.
sudo tee /etc/systemd/system/link_ping_pull_config.service >/dev/null <<'EOF'
[Unit]
Description=Pull the shared link monitor config
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/link_ping_pull_config.env
ExecStart=/usr/local/bin/link_ping_pull_config
# Stays root (it writes the root-owned targets.json) but sandboxed. The three
# ReadWritePaths are exactly what the script writes: the published targets
# directory, /run/lock for its flock file (two ticks must not overlap), and
# the git scratch checkout the hand-run in step 4 created -- all three must
# exist before the unit starts, or ProtectSystem=strict leaves them read-only.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/link_ping_prometheus /run/lock /var/lib/link_ping_pull_config
EOF
sudo tee /etc/systemd/system/link_ping_pull_config.timer >/dev/null <<'EOF'
[Unit]
Description=Pull the shared link monitor config periodically

[Timer]
OnCalendar=*:0/5
Persistent=true
RandomizedDelaySec=15

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now link_ping_pull_config.timer
```

`RandomizedDelaySec` staggers the 10 sites; `Persistent=true` runs a missed
run at the next boot. The script must run as an account that can write the
destination directory (root here); the agent runs as `nobody` and only
reads the file.

##### Windows install

```powershell
# 1. Script and its settings directory (no spaces in the path: the
#    scheduled task's command line must not need quoting).
New-Item -ItemType Directory -Force -Path 'C:\ProgramData\link_ping_prometheus\pull_config' | Out-Null
Copy-Item deploy\mesh\pull-config.ps1 `
  'C:\ProgramData\link_ping_prometheus\pull_config\pull-config.ps1'

# 2. Deploy key, DACL restricted to SYSTEM + Administrators.
Copy-Item \\deploy\secrets\mesh-config-deploy-key `
  'C:\ProgramData\link_ping_prometheus\pull_config\deploy_key'
icacls 'C:\ProgramData\link_ping_prometheus\pull_config\deploy_key' `
  /inheritance:r /grant "*S-1-5-18:F" "*S-1-5-32-544:F"

# 3. known_hosts (verify the fingerprints first), then run once by hand.
Copy-Item \\deploy\secrets\github_known_hosts `
  'C:\ProgramData\link_ping_prometheus\pull_config\known_hosts'
& 'C:\ProgramData\link_ping_prometheus\pull_config\pull-config.ps1'

# 4. Schedule it. Machine-scope env vars give the script its settings.
schtasks /Create /TN "LinkPing config pull" /SC MINUTE /MO 5 /RU SYSTEM `
  /RL HIGHEST /F /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\link_ping_prometheus\pull_config\pull-config.ps1"
```

Settings are machine environment variables (parameters too):

| Variable / parameter | Meaning |
| --- | --- |
| `LINK_PING_CONFIG_REPO` / `-Repo` | SSH clone URL of the config repo |
| `LINK_PING_CONFIG_BRANCH` / `-Branch` | branch to track (default `main`) |
| `LINK_PING_CONFIG_WORK` / `-Work` | scratch checkout directory |
| `LINK_PING_CONFIG_DEST` / `-Dest` | directory holding the live `targets.json` |
| `LINK_PING_CONFIG_KEY` / `-Key` | deploy key path |
| `LINK_PING_CONFIG_KNOWN_HOSTS` / `-KnownHosts` | pinned host keys path |
| `LINK_PING_CONFIG_FILE` / `-File` | filename inside the repo (default `targets.json`) |

A Windows service has no SIGHUP, so `-targets-reload-interval` is what
makes the pulled file take effect; otherwise the agent probes the old
topology until a restart.

## Operability runbook

### Adding a site

1. Append the site to the shared `targets.json` (one line): the repo file
   (pull) or `link_ping_mesh_peers` (push).
2. Deploy it with `-source=<its name>` and the same file.
3. Sites pick the peer up on their next reload (`systemctl reload` is
   immediate on Linux; the poll interval bounds it on Windows).

Peer sites need no edit. See
[Reload semantics](#reload-semantics-what-refreshes-and-what-does-not) for
the one case (a new IP not covered by `-allow`) needing CIDR headroom.

### Renumbering a site

Change the `address` in the shared file and deploy.

- Peers see a normal target change: the loop restarts with the new address
  and the old series are withdrawn (deleted, so Prometheus marks them stale
  — no frozen `link_up=1`, and `absent()`-style alerting works).
- Server-side, the host appears under a new `client` label.
- There is no per-host allowlist to edit; only the startup-time derivation
  below applies.

### Reload semantics: what refreshes and what does not

`-targets-reload-interval` and SIGHUP re-read and re-validate the targets
file. On reload the agent applies the target set — new targets start,
removed targets stop and lose their series, changed ones restart — and
re-applies the self-skip, so the local site is never re-added.

The derived allowlist is built once at startup:

- A new site's probe *into* a peer is accepted only once the peer's
  allowlist contains the new IP: by the peer's next restart, or, with no
  restart, because the IP falls inside a CIDR already in `-allow`.
- `-allow` therefore carries both extra non-mesh hosts and growth headroom;
  CIDRs make adding or renumbering a site restart-free.

### Growth headroom and the 256-entry cap

The allowlist is capped at **256 entries** (exact IPs + CIDRs, summed);
`ParseAllowlist` rejects more and the agent exits at startup. Derived
entries are one per peer, so an all-exact mesh tops out at 257 sites (256
derived entries plus the self-skip; each `-allow` entry lowers it by one).
For restart-free growth, list the site ranges instead:

```sh
OPTIONS="-mode=both -source=site01 -listen=:4000 -metrics=127.0.0.1:2112 -targets=/etc/link_ping_prometheus/targets.json -allow-from-targets -allow=192.0.2.0/24,198.51.100.0/24,203.0.113.0/24 -targets-reload-interval=30s"
```

A CIDR entry costs the precise per-IP bound: a CIDR-matched client gets
dynamic series (capped at `MaxClientSeries` = 1024 IPs per process,
`client_overflow` beyond), TTL-evicted after `DynClientTTL` (10 minutes
idle), so an idle site's counters reset to 0 on return. Exact-IP entries —
the derived ones — are pre-resolved and never evicted. Both need HMAC, or a
spoofer inside the range can pin the 1024 slots.

IPv4-mapped IPv6 entries are unmapped, so `::ffff:10.0.0.1` matches an IPv4
client; a scope zone (`fe80::1%eth0`) is rejected at startup, because a
datagram source never carries one.

### Rotating `-echo-secret`

Servers first, then clients, then drop the old secret — the outage-free
sequence in the [Security](security.md) guide:

1. Keep both secrets on **every** site: `LINK_PING_ECHO_SECRET=<new>` plus
   `LINK_PING_ECHO_SECRET_OLD=<old>` (old acceptance is server-side only).
2. Roll the primary to `<new>` everywhere, restart, remove
   `LINK_PING_ECHO_SECRET_OLD`.
3. Watch `link_server_probes_dropped_total{reason="hmac"}` during the
   half-rotated window so it reads as rotation, not network loss.

Every site is both server and client, so put both secrets on all sites
(step 1) before changing any primary. The agent refuses to start with
`-echo-secret-old` set while `-echo-secret` is empty.

### v0.7 → v0.8 (`-hmac-coverage`)

Tag coverage is client-side; the v0.8 server dual-accepts both coverages
when it has a secret. Upgrade **servers before clients**: a v0.7 server
receiving a `full-frame` payload probe cannot header-verify it and drops
it, which the client reads as loss. Upgrade every site, or confine early
movers with `-hmac-coverage=header` until all reflectors are ≥ v0.8. Do not
mask the mismatch as negotiation — the drop is deliberate real loss. With
`-payload=0` the coverages are byte-identical, so this only bites sites
that use payload probing.

## Sizing reality check at N=10

### Series

Each target exports one series set under `{source, target, address}`: 17
series pre-created by `SeedMetrics` (sent, timed_out, inflight, send_errors,
throttled, corrupted, link_up, rto, srtt, jitter, path MTU, MTU sent, MTU
lost, the three `link_prober_internal_errors_total` reasons, the RTT
histogram, and its bucket/`_sum`/`_count` lines). A
10-site mesh probes 10 × 9 = **90 directional links** — 90 series sets
across the fleet, 9 per agent: small, with the heap soft-capped at 128MiB
and per-target handles resolved once (see [operations and
tuning](operations.md#memory-and-runtime-tuning)).

### Probe traffic

At the 500ms default one target costs 2 probes/s. Counting the echo (same
size as the probe — no amplification), with a 112-bit IPv4 path (20B IP +
8B UDP):

| Frame | Bytes on wire per datagram | 9 peers, 2 probes/s, out+back |
| --- | --- | --- |
| 24B header (no secret) | 52 | ~15 kbit/s per site |
| 32B header (`-echo-secret`) | 60 | ~17 kbit/s per site |
| header + `-payload=1400` | 1460 | ~0.4 Mbit/s per site |

- `-echo-secret` set: ~15–17 kbit/s per site — negligible.
- `-payload=1400`: 0.4 Mbit/s/site, 40× more per-probe bytes, so use it on a
  subset of links rather than the whole mesh. Counts
  `link_probes_corrupted_total` instead of loss for a corrupted echo.
- `-mtu-sweep` (default `1m`, per target): a DF-set binary search each
  interval, ~20–23 attempts per target per sweep (bounded by
  ~2·log2(1400)+2 in `internal/prober/mtu.go`), retried once per failing
  size. Use it where PMTUD breakage is plausible (VPN/overlay/PPPoE); raise
  to `10m` or disable with `0` on a metered WAN. Never enters the loss ratio.
- `-metrics-gzip`: unnecessary here; a 9-target `/metrics` body is small,
  and gzip retains up to ~0.7MB × `GOMAXPROCS` of heap
  ([Flags](../README.md#flags)). Leave it off.

## Scrape path

Each agent's `/metrics` binds `127.0.0.1:2112` — localhost only. Pick one:

- **Per-site scraper (recommended).** Run Grafana Alloy (or any agent) on
  each site, scrape `localhost:2112`, keep the `link_*` series and
  remote-write them to one Prometheus — only outbound authenticated HTTPS
  crosses the network, and every agent shares one `instance` value. See
  [scraping](scraping.md).
- **Direct scrape.** Bind `:2112` and scrape each site's IP: that exposes
  `/metrics` **and** `/status` (whole topology: addresses, packet counts,
  build info) to anything reaching TCP 2112, so it needs Basic auth + TLS or
  a firewall admitting only the monitoring hosts. The Ansible guardrail
  refuses an unauthenticated wildcard bind; `-metrics-user` / `-metrics-pass`
  come from the service environment, and Basic auth over plaintext needs
  `-metrics-allow-insecure` (transport only). See the `instance` caveat in
  [Grafana dashboard on a mesh](#grafana-dashboard-on-a-mesh).

## Prerequisites

| Requirement | Why |
| --- | --- |
| UDP 4000 reachable both ways between every pair of sites | A one-way block shows as loss on one directional series |
| TCP 2112 (or the local scraper) for scrapes | `/metrics`; localhost by default |
| NTP-synchronised clocks (a few seconds is plenty) | With `-echo-secret`, frames more than ±30s from the server clock are dropped as `replay`; peers read `link_up=0` |
| The same `-echo-secret` on every site | A half-configured pairing reads healthy with no reflector authentication |
| One shared, complete `targets.json` on every site | It is both the probe list and the allowlist source |

Clock-skew alerts: `LinkClockSkewHigh`, `LinkClockSkewCritical` and
`ServerReplayDrops` in `rules/link-monitor.yml`.

## Operator caveats

- **Server-side series are keyed by client IP.**
  `link_server_probes_received_total{source,client}` and
  `link_server_clock_skew_seconds{source,client}` carry the remote IP in
  `client` (address only, no port), while client-side families name the
  remote site in `target`; joining them needs a static IP → site map as
  Prometheus relabel rules:

  ```yaml
  metric_relabel_configs:
    - source_labels: [client]
      regex: "192\\.0\\.2\\.11"
      target_label: client_site
      replacement: site01
  ```

  Update the map in the same change as a renumbering.
- **A CIDR-matched client's counters reset** after `DynClientTTL` (10
  minutes idle), so a `rate()` across the return understates that interval.
  Exact-IP entries never reset; do not alert on a raw rate crossing a gap.
- **An IP change changes the `address` label**, so renumbering makes a new
  series set (and a stale one) rather than moving history — deliberate, as a
  frozen series for a gone address is worse.
- **Two sites must not share a `name`**: names are the `target` label and
  the self-skip key, and the loader rejects duplicates.
- **`-allow` is additive and fail-closed.** An empty effective allowlist
  refuses to start rather than admitting everything; there is no "allow
  all" setting.
