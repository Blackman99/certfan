# Command reference

```
certfan check [host[:port] ...]
  -f, --file FILE         read targets from FILE (one host[:port] per line;
                          # comments; optional warn_days=N warn_pct=N
                          starttls=PROTO|none alpn=P1,P2 per line)
  -4 / -6                 restrict to IPv4 / IPv6
  --connect IP[:PORT]     probe these addresses instead of DNS (repeatable, single target)
  --resolver IP[:PORT]    ask this DNS resolver instead of the system one (repeatable;
                          the union of all answers is probed; port defaults to 53)
  --dns-divergence MODE   note|warn|fail: how to treat an address only some resolvers
                          returned (default note: shown, verdict unchanged)
  --starttls PROTO        smtp|imap|pop3|postgres: plaintext preamble before TLS; default
                          port becomes 25 / 143 / 110 / 5432 (465 / 993 / 995 are rejected:
                          they speak TLS directly, so leave --starttls off)
  --alpn P1[,P2...]       offer these ALPN protocols (repeatable); WARN when nodes select
                          different ones
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
  --starttls PROTO        four local smtp/imap/pop3/postgres nodes instead: one stale,
                          one that never offers STARTTLS
certfan --version
```

Exit codes: `0` all pass, `1` worst finding is WARN, `2` any FAIL.

JSON nodes include `chain_fingerprints` (SHA-256 hex, leaf first) and `ocsp_stapled`.
Prometheus adds `certfan_node_ocsp_stapled` and `certfan_node_chain_len`.

With `--resolver`, each JSON node also has `resolvers` (which resolvers returned that address), each host has
`dns: {resolvers, errors, divergent}`, and Prometheus adds `certfan_dns_divergent{host}` (1 when answers differ).

With `--starttls`, hosts have `starttls` (the protocol) and each JSON node has `starttls`, `banner` (the
server's first greeting line, e.g. `220 mx1.example.com ESMTP`) and `error_stage` (`starttls` when the failure
happened before TLS). When no port is given the host label includes the protocol's port (`mx.example.com:25`).

With `--alpn`, hosts have `alpn_offered`, each node has `alpn` (selected protocol or `null`), text output shows
`alpn:h2` / `alpn:-`, and Prometheus adds `certfan_node_alpn_info{host,ip,serial,alpn}` (always 1; `alpn=""`
when the node selected none).
