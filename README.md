<p align="center"><img src="assets/logo.svg" width="96" alt="certfan logo"></p>

# certfan

**Your cert renewed. Did every node get it?**

With 47-day (and Let's Encrypt 6-day) certificates, renewals happen constantly, and the classic failure isn't
"the cert expired", it's *one* load-balancer node, edge POP or replica that never reloaded and still serves the
old certificate. Most uptime checks resolve the hostname once, hit one IP, and report green.

certfan resolves **every** A/AAAA address, does a TLS handshake with the right SNI against each one, and fails
when they don't all serve the same, valid, not-nearly-expired certificate.

![certfan demo](site/demo.gif)

## Install

```bash
pipx install "git+https://github.com/Blackman99/certfan@v0.1.0"   # pure Python 3.9+, zero dependencies
```

## Use

```bash
certfan check example.com api.example.com:8443
certfan demo     # three local nodes, one serving a different cert
```

```
shop.example.com  3 address(es), 2 distinct certificate(s)
  PASS  203.0.113.10   cert A  serial 51fe63574478  expires 2026-11-20  TLSv1.3  41ms
  PASS  203.0.113.11   cert A  serial 51fe63574478  expires 2026-11-20  TLSv1.3  38ms
  FAIL  203.0.113.12   cert B  serial 61c4ec55df4c  expires 2026-10-12  TLSv1.3  44ms
    - 203.0.113.12: serves a different certificate (serial 61c4ec55df4cf8bb, issued 2026-08-13) than the other nodes
  verdict: FAIL
```

Exit codes `0` pass / `1` warn / `2` fail, so it drops into cron, CI or a Kubernetes CronJob.
`--format json`, `--format prom` and `--prom-file` (node_exporter textfile collector) are built in.

Full docs: **https://blackman99.github.io/certfan/docs/** · [Roadmap](ROADMAP.md) · [Goal](GOAL.md) · MIT
