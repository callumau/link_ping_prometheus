# Grafana Alloy Scraping

The example scrapes `/metrics`, keeps only `link_*` metrics (dropping `go_*`
and `process_*` to save bandwidth), and forwards them to
`prometheus.remote_write`.

Add your own `prometheus.remote_write "default"` block; renaming it means
updating the `prometheus.remote_write.default.receiver` reference.

```river
prometheus.scrape "link_ping" {
 targets = [{
  "__address__" = "localhost:2112",
 }]
 metrics_path    = "/metrics"
 scrape_interval = "1m"
 scrape_timeout  = "10s"
 forward_to      = [prometheus.relabel.link_ping_keep.receiver]
}

prometheus.relabel "link_ping_keep" {
 rule {
  source_labels = ["__name__"]
  regex         = "link_.*"
  action        = "keep"
 }
 forward_to = [prometheus.remote_write.default.receiver]
}
```

On different hosts, replace `localhost:2112` with the prober's address. With
metrics basic auth enabled, add a `basic_auth` block to the targets:

```river
prometheus.scrape "link_ping" {
 targets = [{
  "__address__" = "10.0.0.5:2112",
 }]
 ...
 basic_auth {
  username = "monitoring"
  password = "secret"
 }
}
```

## Grafana Dashboard

Prebuilt dashboard: [grafana-dashboard.json](../grafana-dashboard.json) —
Grafana v2 resource format (`dashboard.grafana.app/v2`), needing a Grafana
version that supports it.

- Panels: link status, packet loss, RTT percentiles / average / current,
  adaptive RTO, jitter, throughput, SRTT, path MTU (DF-probed), DF probe loss,
  corruption % (`-payload`), send errors, server probes received/dropped/echo
  errors, clock skew, prober internal errors, metrics auth failures.
- `link_up` transitions are annotated and itemized in the Link State Changes
  table.
- A `source` variable filters per-site panels; the metrics-auth-failure panel
  is unfiltered.

[![Grafana dashboard screenshot](../.docs/screenshot01.png)](../.docs/screenshot01.png)
