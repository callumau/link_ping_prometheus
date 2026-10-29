# Linux (systemd)

Install the hardened unit from the repo — do not hand-write one. It carries
`User=nobody`, the sandboxing (`CapabilityBoundingSet=` empty,
`ProtectSystem=strict`, `PrivateDevices`, `ProtectProc=invisible`,
`RestrictAddressFamilies` including the `AF_NETLINK` that IPv6 `%zone`
resolution needs), and the `time-sync.target` ordering the HMAC replay window
depends on:

```sh
sudo cp installer/linux/link_ping_prometheus.service /etc/systemd/system/
```

It expects the binary at `/usr/local/bin/link_ping_prometheus` and runs as
`User=nobody`/`Group=nogroup` (the Debian default) — edit those two lines if
your distro spells the unprivileged account differently (`nobody`/`nogroup` on
Debian/Ubuntu, `nobody`/`nobody` on RHEL).

Flags go in `OPTIONS` inside `/etc/link_ping_prometheus.env`, never in the
unit's `ExecStart`. Secrets go in the same file as environment variables
(`LINK_PING_METRICS_USER`, `LINK_PING_METRICS_PASS`, `LINK_PING_ECHO_SECRET`),
because a command line is readable through `/proc` and the journal:

```sh
# /etc/link_ping_prometheus.env   (chmod 600)
OPTIONS="-mode=server -listen=:4000 -allow=203.0.113.5 -metrics=127.0.0.1:2112"
```

Keep every flag value space-free: systemd word-splits the unquoted `$OPTIONS`
expansion, so a space inside a value silently truncates the flag list.

`-metrics=127.0.0.1:2112` is deliberate: `/metrics` and `/status` carry the
whole probe topology (target addresses, packet counts, build info), so scrape
through a tunnel or a local agent. A wildcard bind (`-metrics=:2112`) is
readable by every host that can route to the box, so it needs Basic auth
(`-metrics-user`/`-metrics-pass` plus `-metrics-tls-cert`/`-metrics-tls-key`,
or `-metrics-allow-insecure` when keeping plaintext HTTP) or a firewall rule
admitting only the scraper.

`time-sync.target` ordering is load-bearing: with `-echo-secret` set the
server's replay guard uses a 30s timestamp window, so clocks must be roughly
NTP-synchronized. In client/both mode, use an absolute path for `-targets`
(e.g. `-targets=/etc/link_ping_prometheus/targets.json`), and note that
`systemctl reload link_ping_prometheus` (SIGHUP) only works on a unit started
with `-targets`.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now link_ping_prometheus
```
