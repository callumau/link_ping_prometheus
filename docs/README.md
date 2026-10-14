# Documentation

Guides for deploying and operating link_ping_prometheus. The
[main README](../README.md) covers the exporter, its flags, and its metrics; the
pages here go deeper.

## Deployment

| Guide | Use it when |
| --- | --- |
| [Deployment overview](deployment.md) | Choosing between the options below |
| [Windows service](windows-service.md) | Installing as an SCM service — hardening and the enterprise checklist |
| [Linux (systemd)](linux-systemd.md) | Installing the hardened systemd unit |
| [Docker](docker.md) | Running the published container images |
| [Ansible](ansible.md) | Deploying a fleet from a control node |
| [Mesh deployment](mesh-deployment.md) | N sites monitoring each other from one shared targets file |

## Configuration and day-two operations

| Guide | Covers |
| --- | --- |
| [Targets file](targets-file.md) | Target schema, address syntax, hot reload, and one file for a whole mesh |
| [Operations](operations.md) | MTU sweeps, `/healthz`, `/readyz` and `/status` endpoints, memory and runtime tuning |

## Monitoring and alerting

| Guide | Covers |
| --- | --- |
| [PromQL examples](promql.md) | Loss, latency, jitter, baseline shift, link status and outages |
| [Alert rules](alerting.md) | The shipped rules file and dead-source coverage |
| [Scraping](scraping.md) | Prometheus scrape config, Grafana Alloy, and the bundled dashboard |

## Internals

| Guide | Covers |
| --- | --- |
| [Wire protocol](wire-protocol.md) | The 24/32-byte UDP datagram, HMAC coverage, and MTU sweep probes |
| [Security](security.md) | Allowlist, HMAC, the replay window, metrics auth and TLS |
| [Development](development.md) | Building, testing, code structure, and contributing |
