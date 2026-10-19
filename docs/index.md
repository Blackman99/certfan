# certfan

**Probe every IP behind a TLS hostname and catch the node still serving an old, expiring or broken certificate.**

Certificate lifetimes are shrinking (the CA/B Forum path to 47 days; Let's Encrypt offers 6-day certs). Renewal is
now routine, and the common failure is no longer "we forgot to renew". It is: the ACME client renewed, the deploy
hook reloaded *most* of the fleet, and one load-balancer node, edge POP or replica still serves the previous cert.
Typical checks (blackbox_exporter, Uptime Kuma, Gatus, `openssl s_client`) connect to one resolved address, so they
stay green.

certfan:

1. resolves **all** A/AAAA records (or takes explicit backends with `--connect`, or a `-f` targets file),
2. performs a TLS handshake with SNI on **each** address and verifies chain + hostname,
3. compares leaf fingerprints and the presented intermediate chain across nodes,
4. notes OCSP stapling presence per node,
5. warns when a cert has fewer than N days or less than N% of its lifetime left (per-target overrides in `-f`),
6. exits `0`/`1`/`2` and can emit JSON or Prometheus textfile metrics.

```bash
pipx install "git+https://github.com/Blackman99/certfan@v0.3.0"
certfan demo
certfan check example.com
```

Zero dependencies, Python 3.9+, Linux/macOS/Windows.

**Blog:** [Your cert renewed. Did every node get it?](blog/every-node-same-cert.md) ·
[证书续期了，每台节点都换上了吗？](blog/every-node-same-cert-zh.md)
