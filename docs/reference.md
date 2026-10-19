# Command reference

```
certfan check [host[:port] ...]
  -f, --file FILE         read targets from FILE (one host[:port] per line;
                          # comments; optional warn_days=N warn_pct=N per line)
  -4 / -6                 restrict to IPv4 / IPv6
  --connect IP[:PORT]     probe these addresses instead of DNS (repeatable, single target)
  --resolver IP[:PORT]    ask this DNS resolver instead of the system one (repeatable;
                          the union of all answers is probed; port defaults to 53)
  --dns-divergence MODE   note|warn|fail: how to treat an address only some resolvers
                          returned (default note: shown, verdict unchanged)
  --sni NAME              SNI / name to verify (default: target host)
  --cafile FILE           extra CA bundle
  --no-verify             skip chain/hostname verification
  --allow-unreachable     unreachable address = WARN, not FAIL
  --warn-days N           default 7 (overridable per line in -f)
  --warn-pct N            default 33 (overridable per line in -f)
  --format text|json|prom
  --prom-file FILE        also write Prometheus metrics atomically
  --timeout SECONDS       per address, default 5

certfan demo              three local nodes, one with a different cert (always exits 0)
certfan --version
```

Exit codes: `0` all pass, `1` worst finding is WARN, `2` any FAIL.

JSON nodes include `chain_fingerprints` (SHA-256 hex, leaf first) and `ocsp_stapled`.
Prometheus adds `certfan_node_ocsp_stapled` and `certfan_node_chain_len`.

With `--resolver`, each JSON node also has `resolvers` (which resolvers returned that address), each host has
`dns: {resolvers, errors, divergent}`, and Prometheus adds `certfan_dns_divergent{host}` (1 when answers differ).
