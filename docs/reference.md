# Command reference

```
certfan check host[:port] [host[:port] ...]
  -4 / -6                 restrict to IPv4 / IPv6
  --connect IP[:PORT]     probe these addresses instead of DNS (repeatable, single target)
  --sni NAME              SNI / name to verify (default: target host)
  --cafile FILE           extra CA bundle
  --no-verify             skip chain/hostname verification
  --allow-unreachable     unreachable address = WARN, not FAIL
  --warn-days N           default 7
  --warn-pct N            default 33
  --format text|json|prom
  --prom-file FILE        also write Prometheus metrics atomically
  --timeout SECONDS       per address, default 5

certfan demo              three local nodes, one with a different cert (always exits 0)
certfan --version
```

Exit codes: `0` all pass, `1` worst finding is WARN, `2` any FAIL.
