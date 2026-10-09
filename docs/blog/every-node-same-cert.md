---
title: "Your cert renewed. Did every node get it?"
description: Shorter TLS certificate lifetimes make "one load-balancer node still serves the old cert" a routine failure. Single-address checks miss it; certfan handshakes every address behind a hostname and compares what each one serves.
---

# Your cert renewed. Did every node get it?

*October 2026 · [中文](every-node-same-cert-zh.md)*

Your ACME client renewed the certificate at 03:00. The deploy hook copied it out and reloaded the fleet. Your uptime
check is green. And one of the four nodes behind `shop.example.com` is still serving last month's certificate,
because its reload failed, or it was drained during the deploy, or it is a replica in a second region that nobody
wired into the hook.

Nothing breaks yet. The old certificate is still valid for a while. Then it expires, and roughly one request in four
fails with a certificate error, and only for some users, depending on which address their resolver or the load
balancer hands them.

## Why this is getting more common

Certificate lifetimes are shrinking on a published schedule. Under CA/Browser Forum ballot
[SC-081](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/),
the maximum validity of a publicly trusted TLS certificate is:

| Issued on or after | Maximum validity |
|---|---|
| 15 March 2026 | 200 days |
| 15 March 2027 | 100 days |
| 15 March 2029 | **47 days** |

Let's Encrypt has offered opt-in [6-day certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
since January 2026, and plans to move its default from 90 to 45 days.

Renewal itself is solved: ACME clients do it automatically. What is not solved is *distribution*. Every renewal is
another deployment of a new file to every place that terminates TLS for that name: load-balancer nodes, ingress
replicas, edge servers, a forgotten VM behind a second A record. With a 398-day certificate, a node that missed
one reload had months before anyone noticed. With 47-day certificates renewed every few weeks, the same miss
happens many times a year, and the gap between "renewed" and "the stale copy expires" gets short.

## Why your existing check stays green

Most certificate checks do this: resolve the hostname, take one address, handshake, read `notAfter`. That is what
`openssl s_client -connect shop.example.com:443` does, and what a typical blackbox_exporter, Uptime Kuma or Gatus
probe does unless you configure one probe per IP by hand.

If the name resolves to four addresses and only one is stale, a single-address check hits a healthy node three
times out of four, and when it does hit the stale one, the certificate it sees is still valid. Nothing alerts
until the old certificate actually expires.

The question you actually want answered is different: **do all the addresses behind this name serve the same,
valid, not-about-to-expire certificate?**

## What certfan does

[certfan](https://github.com/Blackman99/certfan) is a small CLI (pure Python 3.9+, zero dependencies) that
answers exactly that:

1. Resolve **all** A and AAAA records for each target (or take an explicit list of backends with `--connect`).
2. Open a TLS connection to **each** address, sending the right SNI, and verify chain and hostname.
3. Compare certificate fingerprints across addresses. If they differ, the node serving the minority certificate
   fails (on a tie, the one not serving the most recently issued certificate).
4. Warn when a certificate has fewer than `--warn-days` days (default 7) **or** less than `--warn-pct` percent
   (default 33%) of its total lifetime left. The percentage matters for short-lived certs: a 6-day cert with
   1.5 days left is at 25%, so it should already have been renewed, even though "1.5 days" passes many
   day-based thresholds.
5. Exit `0` (pass), `1` (warn) or `2` (fail), and optionally print JSON or Prometheus metrics.

It only does the TLS handshake. It sends no HTTP request.

## Trying it

```bash
pipx install "git+https://github.com/Blackman99/certfan@v0.1.0"
certfan demo
```

`certfan demo` starts three local TLS servers for the same name, one of them with a different certificate, and
checks them. This is the real output from a run on 9 October 2026:

```text
shop.example.test  3 address(es), 2 distinct certificate(s)
  PASS  127.0.0.1:38255                         cert A  serial 51fe63574478  expires 2126-09-15  TLSv1.3  7ms
  PASS  127.0.0.1:42175                         cert A  serial 51fe63574478  expires 2126-09-15  TLSv1.3  6ms
  FAIL  127.0.0.1:43293                         cert B  serial 61c4ec55df4c  expires 2126-09-15  TLSv1.3  6ms
    - 127.0.0.1:43293: serves a different certificate (serial 61c4ec55df4cf8bb, issued 2026-10-09) than the other nodes
  verdict: FAIL
(demo: exit code would be 2; returning 0)
```

Both certificates are valid and far from expiry, which is exactly the case a single-address expiry check calls
healthy. certfan fails it because the nodes disagree.

### A real hostname

Against `example.com`, from a machine without IPv6 connectivity:

```text
$ certfan check example.com
example.com  4 address(es), 1 distinct certificate(s)
  PASS  104.20.23.154                           cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  36ms
  PASS  172.66.147.243                          cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  31ms
  FAIL  2606:4700:10::6814:179a                 OSError: [Errno 101] Network is unreachable
  FAIL  2606:4700:10::ac42:93f3                 OSError: [Errno 101] Network is unreachable
    - 2606:4700:10::6814:179a: unreachable: OSError: [Errno 101] Network is unreachable
    - 2606:4700:10::ac42:93f3: unreachable: OSError: [Errno 101] Network is unreachable
  verdict: FAIL
$ echo $?
2
```

The name has two A and two AAAA records, and certfan tried all four. The two IPv4 nodes agree. The IPv6
addresses failed because *this machine* has no IPv6 route, and certfan treats an unreachable address as a
failure by default: an address that is published in DNS but cannot be checked is not one you can call healthy.
If you know your probe host lacks IPv6, restrict the family, or downgrade unreachable addresses to warnings:

```text
$ certfan check -4 example.com
example.com  2 address(es), 1 distinct certificate(s)
  PASS  172.66.147.243                          cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  31ms
  PASS  104.20.23.154                           cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  32ms
  verdict: PASS

$ certfan check example.com --allow-unreachable      # same 4 addresses; IPv6 rows become WARN, exit 1
```

### Lifetime percentage

The certificate above was issued on 26 September with a 90-day lifetime. To see the percentage rule fire, raise
the threshold:

```text
$ certfan check -4 example.com --warn-pct 90
example.com  2 address(es), 1 distinct certificate(s)
  WARN  104.20.23.154                           cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  30ms
  WARN  172.66.147.243                          cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  30ms
    - 104.20.23.154: 77.6 days left (86% of a 90-day lifetime)
    - 172.66.147.243: 77.6 days left (86% of a 90-day lifetime)
  verdict: WARN
```

The default of 33% fits common ACME behaviour: clients usually renew once about a third of the lifetime remains,
so a certificate below that is one renewal *should* already have replaced.

### Backends behind one VIP

If the nodes sit behind a single load-balancer address, DNS only shows you the VIP. List the backends yourself;
SNI and hostname verification still use the public name:

```bash
certfan check shop.example.com --connect 10.0.0.7 --connect 10.0.0.8 --connect 10.0.0.9:8443
```

Private CA? Add `--cafile corp-root.pem`. Only care about agreement and expiry? `--no-verify`.

## Running it on a schedule

The exit code is the interface, so certfan fits anywhere a shell command does.

**cron**, mailing only when something is wrong:

```cron
*/15 * * * * certfan check shop.example.com api.example.com > /var/log/certfan.log || mail -s "certfan" ops@example.com < /var/log/certfan.log
```

**Prometheus**, through the node_exporter textfile collector. `--prom-file` writes the file atomically while the
normal text report still goes to stdout. This is real `--format prom` output:

```text
$ certfan check -4 example.com --format prom
# HELP certfan_node_cert_expiry_seconds Unix time the served certificate expires.
# TYPE certfan_node_cert_expiry_seconds gauge
# HELP certfan_node_status 0=pass 1=warn 2=fail per address.
# TYPE certfan_node_status gauge
# HELP certfan_distinct_certs Distinct certificates served across all addresses.
# TYPE certfan_distinct_certs gauge
certfan_node_cert_expiry_seconds{host="example.com",ip="172.66.147.243",serial="01eee6aabb521d5e14fc315fd9985690"} 1798239395
certfan_node_status{host="example.com",ip="172.66.147.243",serial="01eee6aabb521d5e14fc315fd9985690"} 0
certfan_node_cert_expiry_seconds{host="example.com",ip="104.20.23.154",serial="01eee6aabb521d5e14fc315fd9985690"} 1798239395
certfan_node_status{host="example.com",ip="104.20.23.154",serial="01eee6aabb521d5e14fc315fd9985690"} 0
certfan_distinct_certs{host="example.com"} 1
```

```bash
certfan check shop.example.com --prom-file /var/lib/node_exporter/textfile/certfan.prom
```

```yaml
- alert: CertFanOut
  expr: certfan_distinct_certs > 1
  for: 15m
- alert: CertNodeFailing
  expr: certfan_node_status == 2
  for: 15m
```

**CI, after a deploy or on a schedule.** A GitHub Actions job that runs every hour and right after the deploy
workflow finishes (adjust the workflow name to yours). A non-zero exit fails the job, and the JSON report is kept
as an artifact:

```yaml
name: certs
on:
  schedule: [{cron: "17 * * * *"}]
  workflow_run: {workflows: ["deploy"], types: [completed]}
  workflow_dispatch:
jobs:
  certfan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with: {python-version: "3.12"}
      - run: pip install "git+https://github.com/Blackman99/certfan@v0.1.0"
      - run: certfan check -4 shop.example.com api.example.com --format json > certfan.json
      - if: always()
        uses: actions/upload-artifact@v4
        with: {name: certfan, path: certfan.json}
```

GitHub-hosted runners have no IPv6 connectivity, hence `-4` in that example. A CI runner also gives you a second
vantage point, which helps with anycast and GeoDNS, where each location may see different addresses.

## Limits, honestly

- **One vantage point sees one view.** With anycast or GeoDNS, certfan checks what *its* resolver and route
  return. Run it from a few places, or point `--connect` at origin addresses. Comparing several resolvers in one
  run (`--resolver`) is on the [roadmap](https://github.com/Blackman99/certfan/blob/main/ROADMAP.md) for v0.2.
- **Leaf certificate only, for now.** A node serving the right leaf with a different intermediate chain is not
  flagged yet. Per-node chain comparison is planned for v0.2.
- **Direct TLS only.** STARTTLS (SMTP, IMAP, Postgres) is planned for v0.3.
- **It does not renew anything.** That is your ACME client's job. certfan checks that the result arrived everywhere.

## Links

- Code and issues: [github.com/Blackman99/certfan](https://github.com/Blackman99/certfan) (MIT)
- Docs: [usage](../usage.md), [monitoring](../monitoring.md), [command reference](../reference.md)
