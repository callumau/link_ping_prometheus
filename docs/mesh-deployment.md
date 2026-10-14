# Organisation mesh deployment

How to run this UDP link monitor as a full mesh across N sites: every
site probes every other site, so the fleet measures all N×(N−1)
directional paths instead of one star around a central hub. The worked
example is 10 sites.

This guide covers the mesh-specific design (`-allow-from-targets`), the
directionality and metric mapping, config distribution (Ansible push or an
unattended git pull), and the operations runbook. It deliberately does not
repeat the flag reference, runtime tuning or scrape configuration: see
[Flags](../README.md#flags) and [Targets File](../README.md#targets-file) in
the main README, and [operations and tuning](operations.md) and
[scraping](scraping.md) here.

## Concept

A mesh needs three things that hand-maintained point-to-point config makes
painful, and the agent now derives all three from one file:

1. **One shared `targets.json`, deployed unchanged everywhere.** The file
   lists every site, including the local one, as `{"name", "address"}`.
   Sites are identified by `name` (which is also the site's `-source`, and
   therefore the `source` label on every series it exports).
2. **A per-site `-source`.** Only this flag differs between hosts: it is
   the site's identity, the label on its own series, and the key the agent
   matches the shared file against.
3. **A derived, fail-closed allowlist** (`-allow-from-targets`). Instead of
   hand-maintaining the peers allowed to echo off this host, the agent
   derives the allowlist from the target addresses in the same file. Every
   target address must be an IP literal: deriving an allowlist entry from a
   DNS name would need a resolution at config-load time, and config load
   deliberately never touches the network (a reload must not depend on
   DNS), so a name address is a loud startup error naming the target.
   `-allow` is still accepted alongside it and contributes extra entries
   (CIDRs, or hosts that are not mesh sites).

The self-skip closes the loop: the agent drops the target whose `name`
equals its own `-source` (exact match — names are case-sensitive Prometheus
label values), so the one shared file probes only the remote peers.

**Why this matters for operations:** adding site 11, or changing a site's
address, is a single edit to the one shared file. Every agent picks it up
on `-targets-reload-interval` (or SIGHUP on Unix) and starts probing the
new peer — no per-host allowlist edit anywhere, and no per-host config
change to roll out. See
[Reload semantics](#reload-semantics-what-refreshes-and-what-does-not) for
exactly which parts of that take effect without a restart and the one
config choice (site-range CIDRs in `-allow`) that makes the growth path
fully restart-free.

## Worked example: 10 sites

### Sites

The addresses below are from the RFC 5737 documentation ranges. Each site
echoes on UDP 4000 and is listed by the name it uses as `-source`.

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
(default `:4000`). One port per host keeps the allowlist and the targets
file trivially derivable from each other; if a site needed several
addresses, list the site once per address with distinct `name`s and expect
one series set per address.

### The shared `targets.json`

The file below is the whole topology — it is deployed to all 10 sites, and
the allowlist for every site is derived from it, so an address that is not
here is neither probed nor accepted. This is the form to hand-write into
the config repo (Option B) or transcribe into `link_ping_mesh_peers`
(Option A): one object per site, `name` then `address`.

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

The Ansible play (Option A) renders the same object list from
`link_ping_mesh_peers` with Ansible's `to_nice_json` — four-space indent
and keys sorted alphabetically, so the on-host file reads `"address"`
before `"name"`. Whitespace and key order are irrelevant: the agent
parses the file, and what the play guarantees is that the bytes are
identical on every host (which is also what makes the task idempotent and
`--check --diff` quiet). Do not hand-edit the on-host copy under Option A
— the next run rewrites it from the group var.

The optional per-target `interval`/`timeout` overrides described in the
[targets file](targets-file.md) guide work here too,
and are the right tool for a single slow long-haul path in an otherwise
homogeneous mesh.

**`address` must be an IP literal.** `-allow-from-targets` derives an
allowlist entry from every address, and config load never resolves DNS
(a reload must not depend on the network), so a name address is a loud
startup error naming the target:

```text
ERROR msg="Program exited with error" err="target \"site02\"
address \"peer.example.com:4000\" is not an IP literal ...
-allow-from-targets cannot allowlist a DNS name (config load never
resolves); use IP addresses in the mesh targets file, or list the host
in -allow"
```

A host that genuinely has no static address can still be a site: give the
file its numeric address for probing, and add the name-based equivalents
to `-allow` explicitly. The Ansible play asserts the same rule before
touching a host.

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

- `-mode=both` (not `server`): a mesh site must echo its peers *and* probe
  them. `-mode=server` never loads the targets file, so it cannot derive an
  allowlist.
- `-source=site01` is the only per-site value in the whole deployment.
- `-targets-reload-interval=30s` applies new peers without a restart. On
  Unix, `systemctl reload link_ping_prometheus` (SIGHUP) also works; the
  poll interval is what matters on Windows.
- `-metrics` is listed for clarity; `127.0.0.1:2112` is already the default.
- `-allow` is deliberately absent: the allowlist is derived. Add it only
  for extra CIDRs or non-mesh hosts (see
  [Growth headroom](#growth-headroom-and-the-256-entry-cap)).

Install the unit and the file as described in the
[Linux (systemd)](linux-systemd.md) guide, or use the Ansible
playbook below.

### Windows service install

`-svc=install` snapshots the runtime flags into the service `binPath`, so
the install line is the config. On `site01`, from an elevated prompt:

```powershell
$exe = 'C:\Program Files\LinkPing\link_ping_prometheus.exe'
& $exe -mode=both -source=site01 -listen=:4000 -metrics=127.0.0.1:2112 `
  -targets="C:\Program Files\LinkPing\targets.json" `
  -allow-from-targets -targets-reload-interval=30s `
  -log-file="C:\ProgramData\link_ping_prometheus\logs\service.log" `
  -svc=install
```

Two things the installer will warn about, both load-bearing:

- `-log-file` is **required** in practice: stdout is discarded under the
  SCM, so without it the agent's logs go nowhere. The agent enforces the
  file's DACL itself at startup (SYSTEM, Administrators and the service
  account only) wherever the path points.
- `-echo-secret` is **not** persisted into the service configuration (and
  would be visible on a command line). Deliver it through the service
  environment, then restrict that key's ACL — step 3 of the README's
  Windows checklist has the `reg add` calls and the ACL hardening:

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Services\link_ping_prometheus\Environment" `
  /v LINK_PING_ECHO_SECRET /t REG_SZ /d "<shared-secret>" /f
```

- `-targets-reload-interval` is **mandatory** on Windows: a service has no
  SIGHUP, so the poll interval is the only way a pulled or re-pushed
  targets file takes effect without a reinstall.
- Path flags (`-targets`, `-log-file`, `-metrics-tls-*`) are rewritten to
  absolute paths at install time; the SCM starts the service with an
  unrelated working directory, so a relative path would resolve elsewhere.

## Directionality: A→B and B→A are not the same measurement

A probe from site A to site B measures A→B forward plus B→A return. The
reverse probe measures B→A forward plus A→B return: the same two legs with
the roles swapped, and with per-direction queueing, policy routing and
NAT/conntrack state all applied in the opposite order. On an asymmetric
path the two readings differ substantially, which is exactly what a mesh
exists to show. Neither one is redundant.

Each direction is exported by exactly one agent:

| Measurement | Exported by | Series |
| --- | --- | --- |
| A→B | **A's** agent | `link_up{source="siteA", target="siteB", address="<B>:4000"}` |
| B→A | **B's** agent | `link_up{source="siteB", target="siteA", address="<A>:4000"}` |

`source` is always the local site (the agent's `-source`), `target` the
remote site, and `address` the remote `ip:port` — the address is part of
the series identity, so changing a site's IP withdraws the old series on
reload and starts a new one (see [Renumbering a site](#renumbering-a-site)).

The RTT is measured client-side with a monotonic clock, so a mesh needs no
clock agreement for its latency numbers. Clock agreement matters only for
the HMAC replay window (see [Prerequisites](#prerequisites)).

### Grafana dashboard on a mesh

The bundled [dashboard](../grafana-dashboard.json) has three template
variables, all `label_values(...)` queries against `link_up`:

| Variable | Query | Selection | Mesh use |
| --- | --- | --- | --- |
| `source` | `label_values(link_up,source)` | multi-select, `All` | the local site(s) |
| `target` | `label_values(link_up,target)` | multi-select, `All`, custom values allowed | the remote site(s) |
| `instance` | `label_values(link_up,instance)` | **single-select, no `All`** | the scrape endpoint |

Every per-link panel filters on all three
(`link_up{instance=~"$instance", target=~"$target", source=~"$source"}`),
so `source=site01, target=site04` is exactly the site01→site04 direction
(site04's agent also has a `source=site04, target=site01` series — a
different direction, and the dashboard will not mix them). Selecting
several sources and targets shows that cross-product, which is how you get
"all links into site04" or "all inter-region links" on one screen.

`instance` is the exception to watch: it is single-select with no `All`,
because it identifies the scrape endpoint, not a link. With the per-site
scraper pattern below every agent is scraped as `localhost:2112`, so all
sites share one `instance` value and the mesh is selected purely by
`source`/`target`. If instead you scrape each agent by its own address,
`instance` becomes per-site and — being single-select — pins the whole
dashboard to one agent. Either keep the per-site scrape pattern, or extend
the dashboard's `instance` variable with `includeAll` and a regex if you
need the direct-scrape layout.

Useful mesh queries (numerator and denominator windows must match):

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
HMAC-SHA256 and expands the wire frame from 24 to 32 bytes. The mesh
worked example includes site addresses only, so the allowlist alone would
have to carry reflector protection. Set the secret everywhere.

If one side is missing it, **the fleet still reads healthy**, which is the
danger:

- A server without `-echo-secret` accepts the client's 32-byte HMAC frame
  as a bounded payload probe and echoes it back. The client verifies the
  echo and reports a fine link. No `hmac` drop reason appears, `link_up`
  stays 1, and there is no reflector authentication at all.
- The shape *is* counted: `link_server_unauth_hmac_frames_total{source}` on
  that server, and `LinkMonitorReflectorUnauthenticated` in
  `rules/link-monitor.yml` alerts on it. That counter is the only signal a
  half-configured pairing produces — load the rule everywhere.
- A secret-less 24-byte header plus exactly 8 bytes of payload has the same
  shape and is counted too, so rule out an 8-byte payload before
  reconfiguring.

Allowlist and HMAC are complementary controls, and a broad allowlist is
only safe with the secret set:

- The allowlist is fail-closed and rejects a source before any crypto or
  metric work, so it is the cheap control.
- HMAC is what makes the entry meaningful: without it, anyone able to spoof
  an allowlisted source can reflect probes 1:1 off the host (the echo is
  never larger than the probe, so this is not an amplifier — but it is a
  reflector).
- With a CIDR entry in `-allow`, a source inside that range that passes
  authentication also allocates **dynamic** server-side series up to
  `MaxClientSeries` (`link_server_probes_received_total`,
  `link_server_clock_skew_seconds`, 1024 distinct IPs per process). Beyond
  that, further new IPs are dropped as `client_overflow`. HMAC is what
  stops an off-path spoofer from spending those slots and evicting real
  peers — unauthenticated frames from inside an allowed CIDR never reach
  the series allocation.

Never rotate the secret by editing only some sites: read the
[Security](security.md) guide's rotation runbook before
touching it.

## Config distribution

Two supported paths; pick one per fleet. They are alternatives, not layers
— if both run, the pull overwrites whatever Ansible pushed at the next
tick.

### Option A: Ansible push (`deploy/ansible/mesh.yml`)

The dedicated mesh playbook. It is driven by one group var, shared by every
host, and writes the identical `targets.json` byte for byte on each site:

```yaml
# group_vars/mesh.yml
link_ping_mesh_peers:
  - {name: site01, address: "192.0.2.11:4000"}
  - {name: site02, address: "192.0.2.12:4000"}
  # ... all 10 sites, including the one you are deploying
```

Identity mapping: each host's own site comes from the `link_ping_site` host
var, falling back to `inventory_hostname`, and must equal one of the
`name`s in `link_ping_mesh_peers` (the play asserts it — the binary's
self-skip is an exact match, so a typo would make a site probe itself and
export a loopback RTT). So the inventory is:

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

The play mirrors `deploy/ansible/playbook.yml` for everything that is not
mesh-specific (binary install, the shipped hardened systemd unit,
`/etc/link_ping_prometheus.env`, the Windows `-svc=install` path, `sc.exe`
hardening, log-dir ACL, SCM `Environment` delivery of the secret, UDP 4000
firewall rule, handlers that restart only on change). See
[deploy/ansible/README.md](../deploy/ansible/README.md) for
prerequisites, the guardrails, the WinRM CA pinning and the
secret-handling rules.

The mesh-specific parts are: the shared targets file, `-allow-from-targets`
(plus the self-skip it implies), the mandatory reload interval, and the
site-identity assertions.

### Option B: unattended pull from a GitHub repo

For fleets without a configuration-management control plane, or when the
topology file should be edited by whoever owns the network rather than by
whoever owns Ansible: keep `targets.json` in a dedicated git repo and have
each site pull it on a schedule with a **read-only deploy key**.

`deploy/mesh/pull-config.sh` (POSIX sh, Linux) and
`deploy/mesh/pull-config.ps1` (Windows) do the same thing:

1. Clone the repo shallowly on first run, then `fetch` + `reset --hard`
   onto the branch. The checkout is a scratch directory; the live file is
   never written by git.
2. Validate the pulled file parses as JSON **before** touching the live
   file. A parse failure leaves the previous file in place and exits
   non-zero, and the agent's own reload validation would keep running the
   previous set anyway — two independent checks, because a truncated
   config that half-applies is a silent fleet-wide failure.
3. Install it atomically: copy into the destination directory as a
   temporary file, then `rename`/`mv` over the live path. A rename within
   one directory is atomic, so the running agent never reads a
   half-written file (the reload either sees the old file or the new one).
4. Serialise runs with a lock, so a timer firing while a slow clone is in
   flight cannot race.
5. Log to stderr (which systemd/the Task Scheduler captures) and to
   syslog/Event Log, and never print the key or its contents.

#### Repo and key hygiene

- **The config repo contains no secrets.** It holds topology only: site
  names and addresses. The HMAC secret and metrics credentials never go
  here — they are delivered through the service environment (Ansible) or
  the SCM `Environment` key / `EnvironmentFile` (manual).
- Create a dedicated **deploy key** with read-only access to that one
  repository (GitHub: repo → Settings → Deploy keys, leave "Allow write
  access" unchecked). Read-only is not a formality: the host holding it is
  a monitored site, and a write-capable key would let anyone who reaches
  that host author the topology of the whole fleet.
- Pin the server key. Ship a `known_hosts` file containing the GitHub SSH
  host keys and pass it to the script; both scripts run ssh with
  `StrictHostKeyChecking=yes` and an explicit `UserKnownHostsFile`, so a
  key you did not pin is refused rather than trusted on first use.
- The private key file must be mode `0600` (Linux) / not readable by broad
  local principals (Windows DACL). Both scripts refuse a key they consider
  exposed, because ssh would refuse it anyway — failing early with a
  readable message beats a bare `Permission denied (publickey)`.

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

`RandomizedDelaySec` staggers the 10 sites so they do not all hit GitHub in
the same second; `Persistent=true` makes a missed run (host off) happen at
the next boot instead of waiting a full period.

The script's own writability requirement: it must run as an account that
can write the **destination directory** (root here). The agent runs as
`nobody` and only reads the file.

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
  /inheritance:r /grant "SYSTEM:F" "Administrators:F"

# 3. known_hosts (verify the fingerprints first), then run once by hand.
Copy-Item \\deploy\secrets\github_known_hosts `
  'C:\ProgramData\link_ping_prometheus\pull_config\known_hosts'
& 'C:\ProgramData\link_ping_prometheus\pull_config\pull-config.ps1'

# 4. Schedule it. Machine-scope env vars give the script its settings.
schtasks /Create /TN "LinkPing config pull" /SC MINUTE /MO 5 /RU SYSTEM `
  /RL HIGHEST /F /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\link_ping_prometheus\pull_config\pull-config.ps1"
```

Settings for the Windows script are machine environment variables (the
script also takes the same names as parameters):

| Variable / parameter | Meaning |
| --- | --- |
| `LINK_PING_CONFIG_REPO` / `-Repo` | SSH clone URL of the config repo |
| `LINK_PING_CONFIG_BRANCH` / `-Branch` | branch to track (default `main`) |
| `LINK_PING_CONFIG_WORK` / `-Work` | scratch checkout directory |
| `LINK_PING_CONFIG_DEST` / `-Dest` | directory holding the live `targets.json` |
| `LINK_PING_CONFIG_KEY` / `-Key` | deploy key path |
| `LINK_PING_CONFIG_KNOWN_HOSTS` / `-KnownHosts` | pinned host keys path |
| `LINK_PING_CONFIG_FILE` / `-File` | filename inside the repo (default `targets.json`) |

A Windows service has **no SIGHUP**, so `-targets-reload-interval` on the
service is what makes the pulled file take effect. Without it the pull
succeeds and the agent keeps probing the old topology until someone
restarts the service — the worst kind of silent staleness, because the
config file on disk looks right.

## Operability runbook

### Adding a site

1. Append the new site to the shared `targets.json` (one line) — the repo
   file if you use the pull model, `link_ping_mesh_peers` in
   `group_vars/mesh.yml` if you push.
2. Deploy the new site with `-source=<its name>` and the same file. First
   start gives it the full derived allowlist immediately.
3. Existing sites pick the new peer up on their next reload: they start
   probing it and create its series. `systemctl reload link_ping_prometheus`
   on Linux makes that immediate; on Windows the poll interval bounds it.

Peer sites need no edit: their allowlist is derived from the same file, and
`-allow-from-targets` is the point of the design. See
[Reload semantics](#reload-semantics-what-refreshes-and-what-does-not) for
the one case (a new IP not covered by `-allow`) where the inbound direction
needs the CIDR headroom described below.

### Renumbering a site

Change the `address` in the shared file and deploy:

- The peers' probing side is a normal target change: the probe loop is
  restarted with the new address and the **old series is withdrawn** on
  reload (a removed/changed target's series are deleted, so Prometheus
  marks them stale — no frozen `link_up=1` for an address that no longer
  exists, and `absent()`-style alerting works). The `address` label is part
  of the series identity, so the new address is a new series.
- Server-side, the renumbered host appears under a new `client` label from
  the peers' point of view (its IP changed).
- In the old per-host-`-allow` model this edit also meant touching (or at
  least restarting) every peer that hard-coded the old IP. With the derived
  allowlist there is no per-host allowlist to edit at all; the only
  remaining consideration is the startup-time derivation covered in the
  next section.

### Reload semantics: what refreshes and what does not

`-targets-reload-interval` and SIGHUP re-read and re-validate the targets
file. On reload the agent applies the target set (new targets start,
removed targets stop and lose their series, changed ones restart), and the
mesh self-skip is re-applied through the same filter as at startup, so the
local site is never re-added as a probe target.

The derived allowlist itself is built once at startup from that file. Two
consequences worth planning for:

- A **new** site's probe *into* a peer is accepted by that peer only after
  the peer's allowlist contains the new IP. Since the allowlist is derived
  at startup, a brand-new IP is admitted either by the peer's next restart
  or — without any restart — because it falls inside a CIDR already listed
  in `-allow`.
- `-allow` therefore does two jobs in a mesh: extra non-mesh hosts, and
  growth headroom for the site ranges. Carrying your site ranges as CIDRs
  is what makes adding or renumbering a site the single-edit, no-restart
  operation the design is for.

### Growth headroom and the 256-entry cap

The allowlist is capped at **256 entries** (exact IPs + CIDRs, summed) —
`ParseAllowlist` rejects a larger list and the agent exits at startup. The
derived entries are one per peer, so a fully exact mesh tops out at 257
sites (256 peers + the site's own self-skip makes 256 derived entries; add
any `-allow` entry and the real limit is one fewer). Beyond that, and
whenever you want growth without restarts, list the site ranges instead:

```sh
OPTIONS="-mode=both -source=site01 -listen=:4000 -metrics=127.0.0.1:2112 -targets=/etc/link_ping_prometheus/targets.json -allow-from-targets -allow=192.0.2.0/24,198.51.100.0/24,203.0.113.0/24 -targets-reload-interval=30s"
```

`-allow` contributes *alongside* the derived entries, so this is additive,
not a replacement. A CIDR entry costs the precise per-IP bound: a
CIDR-matched client gets dynamic series (resolved on demand, capped at
`MaxClientSeries` = 1024 distinct IPs per process, `client_overflow` beyond
that) and those series are TTL-evicted after `DynClientTTL` (10 minutes
idle), so an idle site's server-side counters reset to 0 when it comes
back. Exact-IP entries — the derived ones — are pre-resolved at startup and
never evicted. That is the trade: exact entries give stable server-side
series, CIDRs give restart-free growth; use CIDRs for the ranges you grow
inside, and rely on the derived exact entries for the mesh you actually
run.

Both together are safe only with HMAC: an authenticated-but-CIDR-matched
source is what consumes the 1024 series slots, so without `-echo-secret` a
spoofer inside the range can pin them (`client_overflow` for real peers).

IPv4-mapped IPv6 entries and zone suffixes are handled exactly as the
README's Security section describes: entries are unmapped, so a
`::ffff:10.0.0.1` entry matches an IPv4 client, and a scope zone
(`fe80::1%eth0`) is rejected at startup because a datagram source never
carries one.

### Rotating `-echo-secret`

Servers first, then clients, then drop the old secret — the outage-free
sequence in the [Security](security.md) guide:

1. Add the new secret and keep the old one on **every** site:
   `LINK_PING_ECHO_SECRET=<new>` plus `LINK_PING_ECHO_SECRET_OLD=<old>`
   (the old acceptance is server-side only), and restart.
2. Roll the primary secret to `<new>` everywhere and restart; remove
   `LINK_PING_ECHO_SECRET_OLD`.
3. Watch `link_server_probes_dropped_total{reason="hmac"}` for the
   half-rotated window — that counter is how a fleet mid-rotation is
   visible instead of reading as network loss.

In a mesh every site is both a server and a client, so "servers first"
means: put both secrets on all sites first (step 1) before changing any
primary. The agent refuses to start with `-echo-secret-old` set while
`-echo-secret` is empty, so a deploy that loses the new secret fails loudly
instead of running unauthenticated.

### v0.7 → v0.8 (`-hmac-coverage`)

Tag coverage is client-side; the v0.8 server dual-accepts both coverages
whenever it has a secret. Upgrade order is therefore **servers before
clients**: a v0.7 server receiving a `full-frame` payload probe cannot
header-verify it and drops it, which the client reads as loss. Bringing a
mesh from v0.7 to v0.8 therefore means upgrading every site (an
intermediate window where a site is a fresh v0.8 server while other sites
are still v0.7 clients is fine), or confining the early-mover clients with
`-hmac-coverage=header` until all reflectors are ≥ v0.8. Do not mask the
mismatch as negotiation: the drop is deliberate and reads as real loss.
With `-payload=0` the two coverages are byte-identical, so this only bites
mesh sites that also use payload probing.

## Sizing reality check at N=10

### Series

Each target exports one series set under `{source, target, address}`
(13 series pre-created by `SeedMetrics` — sent, timed_out, inflight,
send_errors, throttled, corrupted, link_up, rto, srtt, jitter, path MTU,
MTU sent, MTU lost — plus the RTT histogram's bucket/`_sum`/`_count`
lines; `link_prober_internal_errors_total` appears only after a prober
fault). A 10-site mesh probes 10 × 9 = **90 directional links**, i.e. 90
series sets in total across the fleet, 9 on each agent. That is small for
a Prometheus, and small for the agent: the heap is soft-capped at 128MiB
and per-target handles are resolved once (see
[operations and tuning](operations.md#memory-and-runtime-tuning)).

### Probe traffic

At the 500ms default, one target costs 2 probes/s. Counting the echo as
well (the echo is the same size as the probe — no amplification), with a
112-bit IPv4 path (20B IP + 8B UDP):

| Frame | Bytes on wire per datagram | 9 peers, 2 probes/s, out+back |
| --- | --- | --- |
| 24B header (no secret) | 52 | ~15 kbit/s per site |
| 32B header (`-echo-secret`) | 60 | ~17 kbit/s per site |
| header + `-payload=1400` | 1460 | ~0.4 Mbit/s per site |

So a mesh with the secret set is on the order of 15–17 kbit/s of probe
traffic per site — negligible. `-payload=1400` is a different matter: at
0.4 Mbit/s/site it costs real WAN bandwidth and 40× more per-probe bytes,
which is why payload probing suits a subset of links (the ones whose data
path you are trying to prove) rather than the whole mesh. `-payload` also
counts `link_probes_corrupted_total` instead of loss for a corrupted echo,
so the loss ratio stays honest where it is enabled.

`-mtu-sweep` (default `1m`, per target) runs a DF-set binary search each
interval: about 20–23 probe attempts per target per sweep (bounded by
~2·log2(1400)+2 in `internal/prober/mtu.go`), retried once per failing
size, with the larger frames near full size. Across 9 peers that is a
steady stream of full-size DF probes on top of the main traffic, on the
same order as the main probes in bytes. It is worth it on paths where
PMTUD breakage is plausible (VPN/overlay/PPPoE), and it is the right thing
to raise to `10m` or disable with `0` on a metered WAN. Its counters never
enter the loss ratio.

`-metrics-gzip` is not needed at this scale: a 9-target agent's `/metrics`
body is small, and gzip costs up to ~0.7MB × `GOMAXPROCS` of retained heap
(see the flag's row in [Flags](../README.md#flags)). Leave it off.

## Scrape path

Each agent's `/metrics` binds `127.0.0.1:2112` by default — localhost only.
For a 10-site mesh, pick one:

- **Per-site scraper (recommended).** Run Grafana Alloy (or any agent) on
  each site, scrape `localhost:2112`, keep the `link_*` series and
  remote-write them to one Prometheus. This is the pattern in the README's
  [scraping](scraping.md) guide,
  and it keeps the management plane off the WAN: only outbound remote-write
  (HTTPS, authenticated) traverses the network, and every agent appears
  under the same `instance` value, which is what the dashboard's
  single-select `instance` variable expects.
- **Direct scrape.** Bind `:2112` and have Prometheus scrape each site's
  IP. That exposes `/metrics` **and** `/status` (the whole probe topology:
  every address, packet counts, build info) to anything that can reach TCP
  2112, so it needs Basic auth + TLS (or a firewall that only admits the
  monitoring hosts). The Ansible play's pre-flight guardrail refuses an
  unauthenticated wildcard bind for exactly this reason; `-metrics-user` /
  `-metrics-pass` come from the service environment, and Basic auth over
  plaintext additionally needs `-metrics-allow-insecure` (which only relaxes
  the transport — it does not make an unauthenticated bind safe).
  Note the `instance` variable caveat in
  [Grafana dashboard on a mesh](#grafana-dashboard-on-a-mesh) for this
  layout.

## Prerequisites

| Requirement | Why |
| --- | --- |
| UDP 4000 reachable *in both directions* between every pair of sites | The mesh probes every pair; a one-way block shows up as loss on exactly one of the two directional series, which is what makes the mesh diagnostic |
| TCP 2112 (or the local scraper) for scrapes | `/metrics`; localhost by default |
| NTP-synchronised clocks (a few seconds is plenty) | With `-echo-secret`, the server drops frames whose embedded timestamp is more than ±30s from its own clock. A drifted site's legitimate probes are dropped as `replay` and its peers read `link_up=0`. `LinkClockSkewHigh` / `LinkClockSkewCritical` / `ServerReplayDrops` in `rules/link-monitor.yml` alert on it |
| The same `-echo-secret` on every site | A half-configured pairing reads healthy while providing no reflector authentication — see above |
| One shared, complete `targets.json` on every site | It is both the probe list and the allowlist source |

## Operator caveats

- **Server-side series are keyed by client IP.** `link_server_probes_received_total{source,client}`
  and `link_server_clock_skew_seconds{source,client}` carry the *remote*
  IP in `client` (address only, no port), while the client-side families
  name the remote site in `target`. Joining the two sides needs a static
  IP → site map. Keep it next to the dashboard as Prometheus
  metric relabel rules, e.g. one rule per site:

  ```yaml
  metric_relabel_configs:
    - source_labels: [client]
      regex: "192\\.0\\.2\\.11"
      target_label: client_site
      replacement: site01
  ```

  The map is static because the mesh's addresses are static; when you
  renumber a site, update this map in the same change.
- **A CIDR-matched client's server-side counters reset.** If a peer is
  admitted by a CIDR in `-allow`, its `link_server_probes_received_total`
  and `link_server_clock_skew_seconds` series are deleted after
  `DynClientTTL` (10 minutes idle) and re-created at 0 on return, so a
  `rate()` window spanning the return understates that interval. Exact-IP
  entries — the derived ones — are never evicted. Do not alert on a raw
  rate crossing a gap; that is a known counter reset, not loss.
- **The `address` label changes when an IP changes**, so a renumbering
  produces a new series set (and a stale one) rather than moving history.
  That is deliberate — a frozen series for an address that no longer exists
  would be worse.
- **Two sites must not share a `name`.** Names are the series `target`
  label and the self-skip key; a duplicate makes the shared file ambiguous
  (and the loader rejects duplicate names outright).
- **`-allow` is additive and still fail-closed.** An empty effective
  allowlist refuses to start rather than admitting everything. There is no
  "allow all" setting, on purpose.
