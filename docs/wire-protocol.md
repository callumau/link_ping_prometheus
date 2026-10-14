# Wire Protocol

UDP datagram, 24 bytes per probe (32 bytes when `-echo-secret` is set on both
ends, plus an optional payload extension when `-payload` is set on the client):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Magic header `LNKPING\x00` |
| 8 | 8 | Sequence number (little-endian uint64) |
| 16 | 8 | Client timestamp (Unix ns, little-endian uint64) |
| 24 | 8 | HMAC-SHA256 tag (first 8 bytes; only with `-echo-secret`) |
| 24/32 | ≤1400 | Optional pattern payload (with `-payload`): deterministic bytes from seq/ts, client-validated byte-for-byte on echo. |

The server validates the magic header and accepts the header frame plus any
bounded payload extension (header ≤ size ≤ header + 1400 bytes) before echoing;
anything smaller or larger is dropped silently. Payload corruption is detected
client-side and counted separately from loss.

The client additionally requires the echoed timestamp to exactly match the value
it sent — corrupted, replayed, or spoofed responses are discarded and counted as
loss on timeout, protecting RTT samples from poisoning.

**HMAC pairing.** `-echo-secret` must be set on **both** ends. A server running
without it cannot distinguish a 32-byte HMAC frame from a payload probe — 32
falls inside the accepted `header ≤ size ≤ header + 1400` range — so it echoes
the frame unverified.

A half-configured fleet therefore reads healthy with no probe authenticated:
nothing lands in `link_server_probes_dropped_total{reason="hmac"}`, and the
allowlist is the only thing gating the reflector. The server makes the pairing
metric-visible instead: every HMAC-shaped frame it receives without a secret is
counted in `link_server_unauth_hmac_frames_total`, and
`LinkMonitorReflectorUnauthenticated` in `rules/link-monitor.yml` alerts on it.

A secret-less 24-byte header plus exactly 8 bytes of payload has the same shape
and is counted too. The server logs a startup warning when `-echo-secret` is
unset.

**Tag coverage (`-hmac-coverage`).** The 32-byte frame layout and the header tag
position are fixed — the flag changes only what the tag is computed OVER. The default (since v0.8.0) is
`full-frame`: the tag covers the header plus the pattern payload (the 8-byte tag
slot itself is skipped), so a payload tampered in flight, or a different payload
riding a captured header tag, no longer authenticates.

The `-hmac-coverage=header` escape hatch covers the 24-byte header only, and its
wire output is byte-identical to v0.7.0.

The server accepts BOTH coverages for payload frames whenever it has
`-echo-secret`: it tries the header tag first, then full-frame, both
constant-time. A bare 32-byte frame skips the second check, since the two
coverages coincide byte-for-byte there.

Both coverages produce identical tags for zero-payload frames.

Working pairings:

- A `header`-coverage client (v0.7 as deployed) with any server — unchanged.
- Any client with an upgraded server (≥ v0.8).
- An upgraded client with an upgraded server.

The one broken pairing is a v0.7 server with a `full-frame` client (any v0.8
default client). The old server checks the header tag only, cannot verify a
full-frame tag over a payload, drops the frame, and the client reads pure loss.

Upgrade servers to ≥ v0.8 BEFORE (or together with) clients; until the server is
upgraded, confine the client with `-hmac-coverage=header` instead of delaying
the upgrade. There is deliberately no new drop reason: a drop is a drop, both
coverages fail together on a wrong secret, and splitting the reason would
fragment the `hmac`/`replay` misconfig alerting for a distinction the operator
cannot act on.

**Rate limits and re-dial.** The server rate-limits echo processing to 2000
packets/s per remote IP and 10000 packets/s globally (fixed one-second window);
excess datagrams are dropped. The window is fixed, not sliding, so a burst straddling a window
boundary can admit up to 2× the cap — treat the caps as ceilings, not a precise
rate.

The probe loop keeps a single connected UDP socket per target, but re-dials
every 5 minutes by default (`-reconnect-interval`, only when no probes are in
flight) so a target hostname that changes IP via DNS is re-resolved. A transient
DNS failure at startup is retried, not fatal.
