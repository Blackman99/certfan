# Changelog
## v0.4.0 (2026-10-26)
- STARTTLS: `--starttls smtp|imap|pop3|postgres` speaks the plaintext preamble (SMTP `EHLO`/`STARTTLS`, IMAP `CAPABILITY`/`STARTTLS`, POP3 `CAPA`/`STLS`, PostgreSQL `SSLRequest`) before the handshake, so every MX / mail / database node behind one name gets the same per-node certificate comparison. The default port follows the protocol (25 / 143 / 110 / 5432) and is shown in the host label.
- A node that does not advertise STARTTLS, refuses it (`454`, `NO`, `-ERR`, `N`), or times out in the preamble is a FAIL that names the stage, even with `--allow-unreachable`. Plaintext sent after the go-ahead (the STARTTLS response-injection bug class) is refused rather than fed into TLS.
- `--starttls` on 465 / 993 / 995 is a usage error (those speak TLS directly); plain TLS on 25 / 587 / 143 / 110 / 5432 that fails like a plaintext port now says `try --starttls PROTO`.
- ALPN: `--alpn h2,http/1.1` offers protocols and WARNs when nodes select different ones (one node lost h2). Text `alpn:h2`, JSON `alpn` / `alpn_offered`, Prometheus `certfan_node_alpn_info{...,alpn="h2"}`.
- Per-line `starttls=PROTO|none` and `alpn=P1,P2` in targets files; JSON gains `starttls`, `banner`, `error_stage`; text shows the name an SMTP node greets with (`as mx3.example.com`).
- `certfan demo --starttls smtp|imap|pop3|postgres`: four local mail/db nodes, one stale, one without STARTTLS.

## v0.3.0 (2026-10-19)
- Multiple resolvers: `--resolver IP[:PORT]` (repeatable) asks specific DNS resolvers instead of the system one and probes the union of their A/AAAA answers, so GeoDNS / split-horizon nodes the system resolver never shows are checked too. Built-in stub DNS client (UDP, TCP on truncation, parallel), still zero dependencies.
- Each node records which resolvers returned it (`resolvers` in JSON, `via ...` in text when answers differ); hosts get `dns: {resolvers, errors, divergent}` and Prometheus `certfan_dns_divergent`.
- `--dns-divergence note|warn|fail` (default `note`) for fleets where every resolver should agree; a failed resolver is a WARN.

## v0.2.0 (2026-10-12)
- Chain comparison: SHA-256 fingerprints of the presented chain (leaf + intermediates); FAIL when intermediates differ across nodes that share the same leaf (full chain on Python 3.13+ via `get_unverified_chain`; leaf-only fallback + issuer CN check on older Python).
- OCSP stapling presence per node (`ocsp_stapled` in JSON/text; WARN when some nodes staple and others do not). Prometheus: `certfan_node_ocsp_stapled`, `certfan_node_chain_len`.
- Targets file: `certfan check -f hosts.txt` (one `host[:port]` per line, `#` comments, optional per-line `warn_days=N` / `warn_pct=N` overrides).

## v0.1.0 (2026-10-09)
- First release: `certfan check`, `certfan demo`, text/JSON/Prometheus output, exit codes.
