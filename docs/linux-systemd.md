# Linux (systemd)

Create `/etc/systemd/system/link_ping_prometheus.service`:

```ini
[Unit]
Description=Link Ping Prometheus (UDP link monitor)
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
ExecStart=/usr/local/bin/link_ping_prometheus -mode=server -listen=":4000" -allow=203.0.113.5 -metrics=":2112"
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

`time-sync.target` ordering is load-bearing: with `-echo-secret` set the
server's replay guard uses a 30s timestamp window, so clocks must be
roughly NTP-synchronized. Note: In client/both mode, use an absolute path
for `-targets` (e.g., `-targets=/etc/link_ping_prometheus/targets.json`).

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now link_ping_prometheus
```
