# Monitoring

## cron

```cron
*/15 * * * * certfan check -f /etc/certfan/hosts.txt > /var/log/certfan.log || mail -s "certfan" ops@example.com < /var/log/certfan.log
```

## Prometheus (node_exporter textfile collector)

```bash
certfan check shop.example.com --prom-file /var/lib/node_exporter/textfile/certfan.prom
```

Metrics:

- `certfan_node_cert_expiry_seconds{host,ip,serial}`: notAfter as a Unix time
- `certfan_node_status{host,ip,serial}`: 0 pass, 1 warn, 2 fail
- `certfan_node_ocsp_stapled{host,ip,serial}`: 1 if the handshake returned an OCSP staple
- `certfan_node_chain_len{host,ip,serial}`: certificates in the presented chain (leaf first)
- `certfan_distinct_certs{host}`: should be 1

Example alert:

```yaml
- alert: CertFanOut
  expr: certfan_distinct_certs > 1
  for: 15m
```

## CI / after a deploy

```yaml
- run: pipx install "git+https://github.com/Blackman99/certfan@v0.2.0"
- run: certfan check shop.example.com --format json > certfan.json
```

## JSON

`--format json` prints a list with one object per target: `host`, `verdict`, `distinct_certs`, `checked_at`,
`nodes[]` (ip, port, fingerprint, serial, subject_cn, issuer_cn, sans, not_before, not_after, tls_version, ms,
chain_fingerprints, ocsp_stapled, verify_error, error, status) and `findings[]` (level, ip, message).
