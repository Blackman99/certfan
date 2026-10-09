# Goal

**One sentence:** tell you, from one command, whether *every* address behind a TLS hostname serves the same valid,
not-about-to-expire certificate.

## In scope
- Fan-out over all resolved A/AAAA addresses (or explicit `--connect` backends), with SNI.
- Per-node: fingerprint/serial mismatch, chain + hostname verification, expiry and lifetime-percentage warnings.
- Machine-friendly outputs: exit codes, JSON, Prometheus textfile.
- Zero runtime dependencies; runs anywhere Python 3.9+ runs.

## Out of scope
- Issuing or renewing certificates (that's your ACME client).
- Being a full uptime/monitoring dashboard (export to the one you have).
- Generic HTTP checks, vulnerability/cipher scanning (use testssl.sh / sslyze).
