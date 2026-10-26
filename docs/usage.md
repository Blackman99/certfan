# Usage

## Check hostnames

```bash
certfan check example.com                  # port 443, all A + AAAA
certfan check api.example.com:8443 www.example.com
certfan check -4 example.com               # IPv4 only (-6 for IPv6 only)
```

## Targets file

Check many hosts from a file (and still accept positional targets):

```bash
certfan check -f hosts.txt
certfan check -f hosts.txt edge.example.com
```

```
# production edges
shop.example.com warn_days=3 warn_pct=25
api.example.com:8443
# staging
staging.example.com warn_days=14
```

Blank lines and `#` comments are ignored. Optional trailing `warn_days=N` / `warn_pct=N`
override the global `--warn-days` / `--warn-pct` for that line only.

## Check explicit backends

When the nodes sit behind one VIP, or DNS returns only some of them, list them yourself:

```bash
certfan check shop.example.com --connect 10.0.0.7 --connect 10.0.0.8 --connect 10.0.0.9:8443
```

SNI and hostname verification use `shop.example.com`. Override with `--sni`.

## Ask several resolvers (GeoDNS, split-horizon)

GeoDNS, latency-based routing and split-horizon DNS give different clients different addresses, so the system
resolver only ever shows you part of the fleet. Ask several resolvers and certfan probes the union:

```bash
certfan check shop.example.com --resolver 1.1.1.1 --resolver 8.8.8.8 --resolver 10.0.0.2
```

```
shop.example.com  3 address(es) from 3 resolvers (answers differ), 2 distinct certificate(s)
  PASS  203.0.113.10   cert A  serial 51fe63574478  expires 2026-11-20  TLSv1.3  chain:2  ocsp  41ms  via 1.1.1.1,8.8.8.8,10.0.0.2
  PASS  198.51.100.4   cert A  serial 51fe63574478  expires 2026-11-20  TLSv1.3  chain:2  ocsp  92ms  via 8.8.8.8
  FAIL  10.0.4.17      cert B  serial 61c4ec55df4c  expires 2026-10-12  TLSv1.3  chain:2  ocsp  3ms  via 10.0.0.2
    - 10.0.4.17: serves a different certificate (serial 61c4ec55df4cf8bb, issued 2026-08-13) than the other nodes
  verdict: FAIL
```

Different answers on their own are normal for GeoDNS, so by default they are only shown. Use
`--dns-divergence warn` (or `fail`) when every resolver should agree, for example to catch a decommissioned
node that is still in one zone. A resolver that times out or returns SERVFAIL is a WARN; NXDOMAIN just means
no addresses. Queries go out over UDP (TCP when the answer is truncated), all resolvers in parallel, with no
extra dependencies. `--resolver` and `--connect` are alternatives.

## Mail servers and databases (STARTTLS)

Behind `mx.example.com` there are usually several MTAs, and behind `db.internal` a primary and replicas. They
renew too, and they forget to reload too. With `--starttls` certfan says hello in plaintext first, asks for TLS,
and then compares certificates exactly as it does for HTTPS:

```bash
certfan check mx.example.com --starttls smtp          # EHLO, STARTTLS        (port 25)
certfan check mail.example.com --starttls imap        # CAPABILITY, STARTTLS  (port 143)
certfan check mail.example.com --starttls pop3        # CAPA, STLS            (port 110)
certfan check db.internal --starttls postgres --cafile corp-root.pem   # SSLRequest (port 5432)
```

```
mx.example.com:25  4 address(es) over SMTP STARTTLS, 2 distinct certificate(s)
  PASS  192.0.2.21   cert A  serial 51fe63574478  expires 2026-11-20  TLSv1.3  chain:2  no-ocsp  38ms  as mx1.example.com
  PASS  192.0.2.22   cert A  serial 51fe63574478  expires 2026-11-20  TLSv1.3  chain:2  no-ocsp  41ms  as mx2.example.com
  FAIL  192.0.2.23   cert B  serial 61c4ec55df4c  expires 2026-10-12  TLSv1.3  chain:2  no-ocsp  44ms  as mx3.example.com
  FAIL  192.0.2.24   server does not advertise STARTTLS (EHLO offered: PIPELINING SIZE 8BITMIME)  as mx4.example.com
    - 192.0.2.24: SMTP STARTTLS failed: server does not advertise STARTTLS (EHLO offered: PIPELINING SIZE 8BITMIME)
    - 192.0.2.23: serves a different certificate (serial 61c4ec55df4cf8bb, issued 2026-08-13) than the other nodes
  verdict: FAIL
```

A node that never advertises STARTTLS, refuses it, or stalls before TLS starts is a FAIL that names the stage, so
a mail relay that quietly fell back to plaintext cannot hide behind `--allow-unreachable`. If a server sends extra
plaintext right after its go-ahead (the STARTTLS response-injection bug class), certfan refuses to start TLS on
that stream. Ports 465 / 993 / 995 already speak TLS directly: check those *without* `--starttls`. Point plain
certfan at port 25 or 5432 by mistake and the error tells you which `--starttls` to add.
`certfan demo --starttls smtp` shows all of this on four local nodes.

## ALPN

`--alpn h2,http/1.1` offers those protocols in the handshake. When nodes select different ones (one replica
rebuilt without HTTP/2, a proxy that lost its h2 config), the odd ones out are a WARN:

```
  WARN  203.0.113.12   cert A  serial 51fe63574478  expires 2026-11-20  TLSv1.3  chain:2  ocsp  alpn:http/1.1  44ms
    - 203.0.113.12: negotiated ALPN http/1.1 while other nodes negotiate h2
```

## What gets flagged

| Finding | Level |
|---|---|
| A node serves a different certificate from the majority (on a tie, from the most recently issued one) | FAIL |
| Same leaf, different presented intermediates (chain mismatch) | FAIL |
| Issuer CN differs across nodes (when full chain is unavailable) | FAIL |
| Chain or hostname verification fails | FAIL |
| Certificate expired | FAIL |
| Address unreachable (WARN with `--allow-unreachable`) | FAIL |
| With `--starttls`: STARTTLS not advertised, refused, or plaintext sent after the go-ahead | FAIL |
| Fewer than `--warn-days` (7) days left, or less than `--warn-pct` (33%) of lifetime left | WARN |
| Some nodes present an OCSP staple and others do not | WARN |
| A `--resolver` timed out or failed | WARN |
| With `--alpn`: a node selects a different ALPN protocol from the others | WARN |
| An address only some `--resolver`s returned (with `--dns-divergence warn` / `fail`) | WARN / FAIL |

The lifetime percentage matters for short-lived certs: a 6-day cert with 1.5 days left is at 25%, which
should already have renewed.

Full certificate-chain capture (leaf + intermediates) needs Python 3.13+ (`get_unverified_chain`).
On 3.9–3.12 certfan still compares the leaf fingerprint and issuer CN.

## Private CAs, self-signed

```bash
certfan check internal.corp:443 --cafile corp-root.pem
certfan check lab.local --no-verify     # only compare + expiry
```
