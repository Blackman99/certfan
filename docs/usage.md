# Usage

## Check hostnames

```bash
certfan check example.com                  # port 443, all A + AAAA
certfan check api.example.com:8443 www.example.com
certfan check -4 example.com               # IPv4 only (-6 for IPv6 only)
```

## Check explicit backends

When the nodes sit behind one VIP, or DNS returns only some of them, list them yourself:

```bash
certfan check shop.example.com --connect 10.0.0.7 --connect 10.0.0.8 --connect 10.0.0.9:8443
```

SNI and hostname verification use `shop.example.com`. Override with `--sni`.

## What gets flagged

| Finding | Level |
|---|---|
| A node serves a different certificate from the majority (on a tie, from the most recently issued one) | FAIL |
| Chain or hostname verification fails | FAIL |
| Certificate expired | FAIL |
| Address unreachable (WARN with `--allow-unreachable`) | FAIL |
| Fewer than `--warn-days` (7) days left, or less than `--warn-pct` (33%) of lifetime left | WARN |

The lifetime percentage matters for short-lived certs: a 6-day cert with 1.5 days left is at 25%, which
should already have renewed.

## Private CAs, self-signed

```bash
certfan check internal.corp:443 --cafile corp-root.pem
certfan check lab.local --no-verify     # only compare + expiry
```
