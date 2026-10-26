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
pipx install "git+https://github.com/Blackman99/certfan@v0.3.0"   # pure Python 3.9+, zero dependencies
```

## Use

```bash
certfan check example.com api.example.com:8443
certfan check -f hosts.txt          # one host[:port] per line; optional warn_days=N warn_pct=N
certfan check example.com --resolver 1.1.1.1 --resolver 8.8.8.8   # probe the union of what each resolver returns
certfan check mx.example.com --starttls smtp      # mail and databases too: smtp, imap, pop3, postgres
certfan check example.com --alpn h2,http/1.1      # and warn when one node stopped negotiating h2
certfan demo     # three local nodes, one serving a different cert
```

Compares leaf fingerprints and the presented chain (intermediates) across every address, and notes OCSP stapling presence per node.
With GeoDNS or split-horizon DNS, one resolver only shows you some of the nodes: repeat `--resolver` and certfan
probes every address any of them returned, and says which resolver handed out which one.
Mail and database fleets drift too: `--starttls smtp|imap|pop3|postgres` speaks the plaintext preamble first
(port defaults to 25 / 143 / 110 / 5432), and a node that stopped offering STARTTLS is a FAIL of its own.

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
