# Deployment

Every deployment option runs the same binary with the same flags, in `server`
(echo), `client` (probes), or `both` mode. Choose the packaging that matches the
site, not the feature set.

The agent needs a working clock either way: with `-echo-secret` set, the server's
replay guard rejects any probe more than 30s from its own clock, so both ends
must be roughly NTP-synchronized.

| Option | Use this when | Guide |
| --- | --- | --- |
| Windows service | The host is Windows Server, and you want SCM crash recovery, a re-ACL'd log directory, and Event Log events. | [Windows service](windows-service.md) |
| Linux systemd | The host runs systemd; the unit orders after `time-sync.target`, which the HMAC replay window depends on. | [Linux (systemd)](linux-systemd.md) |
| Docker | You want the pre-built multi-arch image instead of a host install — one unprivileged container per link. | [Run with Docker](docker.md) |
| Ansible | You are rolling the binary and service definition out to many Linux and/or Windows hosts from an inventory. | [Deployment (Ansible)](ansible.md) |
| Multi-site mesh | Every site carries one identical targets file, derives its allowlist from it, and pulls the config unattended. | [Mesh deployment](mesh-deployment.md) |
