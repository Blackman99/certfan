# Roadmap

## v0.1 (shipped)
- `certfan check host[:port]...`: all A/AAAA, SNI, verify, mismatch, expiry/lifetime-% warnings
- `--connect` explicit backends, `--format text|json|prom`, `--prom-file`, exit codes, `certfan demo`

## v0.2 (shipped 2026-10-12)
- Chain comparison (intermediate mismatch per node), OCSP-stapling presence per node
- Targets file (`certfan check -f hosts.txt`) and per-target thresholds
- Remaining for a later cut: GitHub Action for scheduled checks

## v0.3 (shipped 2026-10-19)
- Multiple resolvers (`--resolver 1.1.1.1 --resolver 8.8.8.8`): probe the union of every resolver's A/AAAA
  answers to catch GeoDNS / split-horizon nodes; per-node resolver attribution, `--dns-divergence note|warn|fail`

## v0.4
- STARTTLS (SMTP/IMAP/Postgres), custom ALPN
- `certfan watch`: loop mode with a tiny /metrics endpoint
- Notifications via webhook on state change

## Later
- CT-log check: "a new cert was issued N hours ago, but node X still serves the previous one"
- GitHub Action for scheduled checks
