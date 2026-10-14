# Security

- The UDP echo server validates the magic header and accepts the header
  frame plus any bounded payload extension (`header ≤ size ≤ header +
  1400`) before echoing it verbatim; out-of-range datagrams are dropped.
  Reflection is 1:1 — the echo is never larger than the probe, so the
  server is not an amplifier — and it rate-limits echo processing per
  source IP and globally. The allowlist is fail-closed
  (no `-allow`, no service) and accepts plain IPs or CIDR prefixes; plain
  IPs keep per-client metric series pre-resolved, while CIDR-matched
  clients are capped at 1024 distinct IPs per process (`client_overflow`
  drops beyond that) so spoofed source rotation cannot grow the label space.
  A sweeper inside the echo loop also expires CIDR-matched clients idle for
  the TTL (10 minutes by default) — on its own timer, so it runs whether or
  not the cap is reached and whether or not any other client is still
  probing. Eviction deletes the client's `link_server_probes_received_total`
  and `link_server_clock_skew_seconds` series, not just its slot: an idle or
  decommissioned peer stops exporting a frozen last value (a skew alert that
  could never resolve). If that client returns, its series are re-created at
  0, so a `rate()` window spanning the return sees a counter reset and
  understates that interval — the accepted cost of bounded cardinality.
  Exact-IP allowlist entries are never evicted; their handles and series are
  pre-resolved at startup.
- Echoed timestamps are validated exactly (see Wire Protocol), so off-path
  corruption and replays cannot fabricate RTT samples.
- With `-echo-secret` set, the server also rejects probes whose embedded
  timestamp is older or newer than ~30 seconds, so a captured probe cannot be
  replayed indefinitely with a spoofed source. This means both nodes must have
  roughly synchronized clocks — NTP is recommended on monitoring endpoints.
- `-hmac-coverage=full-frame` closes payload substitution: a tag computed
  over header+payload means a tampered payload (or a different payload
  riding a captured tag) no longer authenticates at the server. It does
  NOT close tuple replay — a captured frame re-sent within the freshness
  window from another source still authenticates; the dup guard bounds
  what the echo loop can do with it (one echo per (source, seq, ts)
  identity). Sequence tracking / anti-replay state is deliberately not
  attempted: it traps client restarts (seq resets, honest probes read as
  replays) and needs per-client memory a hostile fleet can pin. The
  freshness window stays the replay control.
- Rotation coverage caveat: the rotation runbook above is tested with
  `header` coverage (the default). `full-frame` rotation (rotating the
  secret while clients run `full-frame`) works by the same mechanism —
  the server tries both secrets under both coverages — but is a later
  concern; the acceptance tests pin the header-coverage rotation path.
- `-echo-secret` only protects the link when **both** ends set it. A server
  without it accepts the client's 32-byte HMAC frame as a bounded payload
  probe and echoes it back, so the client reads a healthy link with no
  `hmac` drop reason and no reflector authentication — the allowlist is then
  the only control. The server logs a startup warning when the secret is
  unset; a partially-configured fleet is exactly what that warning surfaces.
- Secret rotation without an outage: with the old secret in the service
  environment of every endpoint, restart the SERVERS with
  `-echo-secret=<new>` plus `-echo-secret-old=<old>` (or
  `LINK_PING_ECHO_SECRET` + `LINK_PING_ECHO_SECRET_OLD`) so frames from
  clients still on either secret are accepted. Then restart the clients
  with `-echo-secret=<new>`. Finally remove `-echo-secret-old` from the
  servers — any frame failing both secrets still counts in
  `link_server_probes_dropped_total{reason="hmac"}` so a half-rotated
  fleet is visible in metrics. The agent refuses to start with
  `-echo-secret-old` set while `-echo-secret` is empty: the old secret
  alone provides no authentication (it is only consulted server-side
  when a primary secret is configured), so a rotation deploy that lost
  the new secret fails loudly instead of running unauthenticated.
- UDP is not amplification-prone (echo is the same size as the request)
  and carries no state, but any internet-facing echo endpoint should be
  firewall-restricted to known monitoring sites.
- The `/metrics` endpoint supports HTTP Basic Auth (`-metrics-user` / `-metrics-pass`) with constant-time comparison over hashed credentials. Both must be set together; the process refuses to start with only one. Usernames must not contain `:` (Basic Auth cannot represent them: the client side is parsed at the first colon, so the user would be unreachable and every request would 401) — the process refuses to start with such a username.
- Prefer the `LINK_PING_METRICS_USER` / `LINK_PING_METRICS_PASS` environment variables over CLI flags — flag values are visible in `ps` to other local users.
- Mode-mismatched flags are not silently ignored: server-only flags (`-allow`, `-listen`, `-echo-secret-old`) set in client mode, and `-targets`/`-target` set together (`-targets` wins), each log a one-line startup warning — backward compatible, but visible.
- Basic Auth without TLS sends credentials as base64 on the wire; a startup warning is logged in that configuration. Use `-metrics-tls-cert` / `-metrics-tls-key` to serve `/metrics` over HTTPS.
- The wire protocol carries no sensitive data (sequence numbers and wall-clock timestamps only) and has no TLS — intended for internal network monitoring. Restrict access with a firewall on untrusted networks.
