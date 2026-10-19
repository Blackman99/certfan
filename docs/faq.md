# FAQ

**Why not blackbox_exporter / Uptime Kuma / Gatus?** They're great, and certfan exports into them. But they probe
one resolved address per check, so a single stale node is invisible unless you hand-configure one probe per IP.

**Anycast / CDN?** From one vantage point you only see the POP you're routed to. Run certfan from a few regions
(CI runners work), or use `--connect` against origin IPs.

**GeoDNS / split-horizon DNS?** Your system resolver returns one view. Repeat `--resolver` (for example a public
resolver plus your internal one) and certfan probes every address any of them returned, tagging each node with
the resolvers that handed it out. Note that `--resolver` changes *which addresses* you learn about, not where the
TLS handshake comes from; for anycast you still need more than one vantage point.

**Does it send HTTP?** No. TLS handshake only, then close.

**Why no `cryptography` dependency?** certfan parses the few X.509 fields it needs with a tiny DER reader so
it installs anywhere, including minimal containers.
