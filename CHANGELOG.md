# Changelog
## v0.2.0 (2026-10-12)
- Chain comparison: SHA-256 fingerprints of the presented chain (leaf + intermediates); FAIL when intermediates differ across nodes that share the same leaf (full chain on Python 3.13+ via `get_unverified_chain`; leaf-only fallback + issuer CN check on older Python).
- OCSP stapling presence per node (`ocsp_stapled` in JSON/text; WARN when some nodes staple and others do not). Prometheus: `certfan_node_ocsp_stapled`, `certfan_node_chain_len`.
- Targets file: `certfan check -f hosts.txt` (one `host[:port]` per line, `#` comments, optional per-line `warn_days=N` / `warn_pct=N` overrides).

## v0.1.0 (2026-10-09)
- First release: `certfan check`, `certfan demo`, text/JSON/Prometheus output, exit codes.
