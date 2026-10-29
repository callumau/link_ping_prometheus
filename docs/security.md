# Security

- The server validates the magic header and accepts the header frame plus a
  bounded payload extension (`header ≤ size ≤ header + 1400`); out-of-range
  datagrams are dropped.
- Reflection is 1:1, so the server is not an amplifier. Echo processing is
  rate-limited to 2000 packets/s per IP and 10000 packets/s globally.
- The allowlist is fail-closed (no `-allow`, no service); entries are IPs or
  CIDRs.
  - Plain IPs keep their series pre-resolved and are never evicted.
  - CIDR-matched clients are capped at 1024 distinct IPs per process; further
    new IPs are dropped as `client_overflow`, so spoofed source rotation cannot
    grow the label space.
  - A sweeper expires CIDR-matched clients idle past the 10-minute TTL.
  - Eviction deletes that client's `link_server_probes_received_total` and
    `link_server_clock_skew_seconds` series; a returning client re-creates them
    at 0, so a `rate()` window across the return sees a counter reset.
- Echoed timestamps are validated exactly (see
  [Wire protocol](wire-protocol.md)); corruption and replays cannot fabricate
  RTT samples.
- With `-echo-secret`, the server drops probes whose timestamp is more than
  ~30 seconds off its clock, so a capture cannot be replayed from a spoofed
  source. Nodes need synchronized clocks (NTP).
- `-hmac-coverage=full-frame` closes payload substitution: a tag over
  header+payload rejects a tampered payload riding a captured tag.
  - It does NOT close tuple replay: a captured frame re-sent from another
    source within the freshness window still authenticates. The dup guard
    allows one echo per (source, seq, ts).
  - Sequence tracking is deliberately not attempted (client restarts, and
    per-client memory a hostile fleet can pin). The freshness window is the
    replay control.
- The rotation runbook is tested with `header` coverage; `full-frame`
  rotation works the same way, but the tests pin only the header path.
- `-echo-secret` protects the link only when **both** ends set it. A server
  without it accepts the client's 32-byte HMAC frame as a bounded payload probe
  and echoes it, so the client reads a healthy link with no `hmac` drop reason
  and no reflector authentication, leaving the allowlist the only control.
  The server warns at startup when the secret is unset.
  - Observability of that half-configured fleet is now partial. Only the bare
    32-byte frame increments `link_server_unauth_hmac_frames_total` (the shape
    `LinkMonitorReflectorUnauthenticated` fires on). A secret-less 24-byte
    header plus *any* payload has the same shape for every payload length
    above 8 bytes, indistinguishable from a legitimate `-payload` probe, so it
    is deliberately not counted: on a `-payload` deployment (payload > 8
    bytes) that alert cannot see a half-configured fleet at all, and the
    allowlist is then the only reflector control. Verify both ends by
    configuration, not by metrics, whenever `-payload` is in use.
- The wire tag is a deliberate 64-bit truncation of HMAC-SHA256, not a
  full-length MAC: guessing it costs 2^64 forgery attempts, and only
  allowlisted sources that survive the pre-authentication global rate charge
  (10000 packets/s) can spend attempts at all. Raising the tag length would
  change the frame size and break every deployed peer — do not.
- `-echo-secret-old` is accepted only alongside a non-empty primary
  `-echo-secret`. An empty old secret is ignored by the server rather than
  installed as a verifier: a zero-length HMAC key is a *valid* key, so
  honouring it would authenticate any frame an off-path attacker tags itself
  (reflection, plus the victim's per-IP budget burned).
- Rotate the secret without an outage:
  1. Restart the SERVERS with `-echo-secret=<new>` plus `-echo-secret-old=<old>`
     (or `LINK_PING_ECHO_SECRET` + `LINK_PING_ECHO_SECRET_OLD`), old secret
     still set everywhere, so either secret is accepted.
  2. Restart the clients with `-echo-secret=<new>`.
  3. Remove `-echo-secret-old` from the servers. Frames failing both secrets
     still count in `link_server_probes_dropped_total{reason="hmac"}`.
  The agent refuses to start with `-echo-secret-old` set while `-echo-secret`
  is empty: the old secret alone authenticates nothing, so a rotation deploy
  that lost the new secret fails loudly.
- Firewall-restrict internet-facing echo endpoints to known monitoring sites.
- `/metrics` supports HTTP Basic Auth (`-metrics-user` / `-metrics-pass`) with
  constant-time comparison over hashed credentials. Both must be set together;
  the process refuses to start with only one.
  - Usernames must not contain `:` (Basic Auth parses at the first colon), or
    every request 401s.
  - Prefer `LINK_PING_METRICS_USER` / `LINK_PING_METRICS_PASS` over flags:
    flags are visible in `ps`.
  - Basic Auth without TLS sends credentials as base64 and logs a warning; use
    `-metrics-tls-cert` / `-metrics-tls-key` for HTTPS.
  - A metrics listener bound to a non-loopback address with no Basic auth logs
    a startup warning: `/metrics` and `/status` publish the probe topology,
    peer IPs and per-link RTT/loss, i.e. the network map itself, to anyone who
    can reach the port. Bind `127.0.0.1`, or set `-metrics-user` /
    `-metrics-pass` with `-metrics-tls-cert`/`-metrics-tls-key` (or
    `-metrics-allow-insecure` to accept plaintext auth), or firewall the port
    to the monitoring hosts. The warning is the entire control — the bind is
    deliberately not refused, because a wildcard metrics port behind a
    scraping-only firewall is a legitimate deployment.
- `-svc=install` validates the configuration *before* it writes the SCM entry,
  through the same checks `run()` applies: an unknown `-mode`,
  `-echo-secret-old` without `-echo-secret`, half of the metrics auth or TLS
  pair, an unloadable TLS pair, or server/both mode with an empty allowlist
  exits non-zero and installs nothing. Those flags are replayed on every
  service start, so freezing a rejected config would have meant a clean
  install followed by an exit 1 every 5 seconds out of the SCM restart ladder,
  with no log to say why when `-log-file` was unset.
- `-targets` is trusted configuration, not inert data: the file steers where
  probes go (a redirected address makes the monitor an oracle for another
  host) and can blank the set outright (an empty array stops all probing).
  `LoadTargets` therefore refuses a symlink — no follow, since following one
  is exactly what a local attacker relies on — and a group/world-**writable**
  file (`chmod o-w,g-w`; `0600` recommended, while `0644` stays accepted
  because reading is not the risk, writing is). On Windows `Perm()` always
  reports `0666`, so only the symlink check applies and the file's DACL is the
  control.
- Mode-mismatched flags log a startup warning: server-only flags (`-allow`,
  `-allow-from-targets`, `-listen`, `-echo-secret-old`) in client mode,
  client-probing flags (`-target`, `-targets`, `-interval`, `-timeout`, …) in
  server-only mode — which is the DEFAULT, so a flag set and not honoured is
  never silent — and `-targets`/`-target` together (`-targets` wins).
- The wire protocol carries no sensitive data (sequence numbers and timestamps
  only) and has no TLS; firewall untrusted networks.
