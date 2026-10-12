"""Turn per-node results into findings, a verdict and output formats."""
from __future__ import annotations

import datetime as _dt
import json
from collections import Counter

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
RANK = {PASS: 0, WARN: 1, FAIL: 2}


def evaluate(host, nodes, warn_days=7.0, warn_pct=33.0, now=None, allow_unreachable=False):
    now = now or _dt.datetime.now(_dt.timezone.utc)
    findings = []  # (level, ip or "*", message)
    good = [n for n in nodes if n.ok]
    for n in nodes:
        if not n.ok:
            findings.append((WARN if allow_unreachable else FAIL, n.addr, f"unreachable: {n.error}"))
            continue
        if n.verify_error:
            findings.append((FAIL, n.addr, f"verification failed: {n.verify_error}"))
        left = (n.not_after - now).total_seconds() / 86400
        life = max((n.not_after - n.not_before).total_seconds() / 86400, 1e-9)
        pct = 100 * left / life
        if left <= 0:
            findings.append((FAIL, n.addr, f"expired {-left:.1f} days ago ({n.not_after:%Y-%m-%d %H:%M} UTC)"))
        elif left < warn_days or pct < warn_pct:
            findings.append((WARN, n.addr, f"{left:.1f} days left ({pct:.0f}% of a {life:.0f}-day lifetime)"))
    fps = Counter(n.fingerprint for n in good)
    if len(fps) > 1:
        top = fps.most_common()
        ref = top[0][0]
        if len(top) > 1 and top[1][1] == top[0][1]:  # tie: trust the most recently issued cert
            ref = max(good, key=lambda n: n.not_before).fingerprint
        for n in good:
            if n.fingerprint != ref:
                findings.append((FAIL, n.addr, f"serves a different certificate (serial {n.serial[:16]}, "
                                 f"issued {n.not_before:%Y-%m-%d}) than the other nodes"))
    # Chain comparison: same leaf, different presented intermediates → FAIL
    chain_nodes = [(n, tuple(n.chain_fingerprints)) for n in good if n.chain_fingerprints]
    chain_counts = Counter(t for _, t in chain_nodes)
    if len(chain_counts) > 1:
        # Group by leaf fingerprint (first element); within each group, flag minority chains
        by_leaf: dict = {}
        for n, t in chain_nodes:
            by_leaf.setdefault(t[0] if t else "", []).append((n, t))
        for _leaf, group in by_leaf.items():
            variants = Counter(t for _, t in group)
            if len(variants) <= 1:
                continue
            ref_chain = variants.most_common(1)[0][0]
            for n, t in group:
                if t != ref_chain:
                    findings.append((FAIL, n.addr,
                        "intermediate chain mismatch (leaf matches, presented intermediates differ)"))
    # Issuer CN divergence (weak chain signal when full chain unavailable on <3.13)
    issuers = Counter(n.issuer_cn for n in good if n.issuer_cn)
    if len(issuers) > 1:
        ref_iss = issuers.most_common(1)[0][0]
        for n in good:
            if n.issuer_cn and n.issuer_cn != ref_iss:
                if any(f[1] == n.addr and ("different certificate" in f[2] or "chain mismatch" in f[2])
                       for f in findings):
                    continue
                findings.append((FAIL, n.addr, f"issuer mismatch (CN {n.issuer_cn!r}, others use {ref_iss!r})"))
    # OCSP stapling presence: warn when some nodes staple and others do not
    stapled = [n for n in good if n.ocsp_stapled]
    unstapled = [n for n in good if not n.ocsp_stapled]
    if stapled and unstapled:
        for n in unstapled:
            findings.append((WARN, n.addr, "OCSP staple missing (other nodes present a staple)"))
    if not nodes:
        findings.append((FAIL, "*", "hostname resolved to no addresses"))
    verdict = max((f[0] for f in findings), key=RANK.get, default=PASS)
    return {"host": host, "verdict": verdict, "distinct_certs": len(fps),
            "nodes": nodes, "findings": findings, "checked_at": now}


def node_level(rep, ip):
    return max((f[0] for f in rep["findings"] if f[1] in (ip, "*")), key=RANK.get, default=PASS)


def render_text(reps, color=False):
    def c(s, code):
        return f"\033[{code}m{s}\033[0m" if color else s
    col = {PASS: "32", WARN: "33", FAIL: "31;1"}
    out = []
    for rep in reps:
        out.append(c(f"{rep['host']}", "1") + f"  {len(rep['nodes'])} address(es), "
                   f"{rep['distinct_certs']} distinct certificate(s)")
        fps = {}
        for n in rep["nodes"]:
            lvl = node_level(rep, n.addr)
            if n.ok:
                tag = fps.setdefault(n.fingerprint, chr(ord("A") + len(fps)))
                chain_n = len(n.chain_fingerprints) or 1
                ocsp = "ocsp" if n.ocsp_stapled else "no-ocsp"
                desc = (f"cert {tag}  serial {n.serial[:12]}  expires {n.not_after:%Y-%m-%d}  "
                        f"{n.tls_version}  chain:{chain_n}  {ocsp}  {n.ms:.0f}ms")
            else:
                desc = n.error
            out.append(f"  {c(lvl.ljust(4), col[lvl])}  {n.addr:<39} {desc}")
        for lvl, ip, msg in rep["findings"]:
            out.append(f"    {c('-', col[lvl])} {ip}: {msg}")
        out.append(f"  verdict: {c(rep['verdict'], col[rep['verdict']])}")
        out.append("")
    return "\n".join(out)


def to_json(reps):
    return json.dumps([{
        "host": r["host"], "verdict": r["verdict"], "distinct_certs": r["distinct_certs"],
        "checked_at": r["checked_at"].isoformat(),
        "nodes": [dict(n.to_dict(), status=node_level(r, n.addr)) for n in r["nodes"]],
        "findings": [{"level": a, "ip": b, "message": m} for a, b, m in r["findings"]],
    } for r in reps], indent=2)


def to_prom(reps):
    lines = ["# HELP certfan_node_cert_expiry_seconds Unix time the served certificate expires.",
             "# TYPE certfan_node_cert_expiry_seconds gauge",
             "# HELP certfan_node_status 0=pass 1=warn 2=fail per address.",
             "# TYPE certfan_node_status gauge",
             "# HELP certfan_node_ocsp_stapled 1 if the node returned an OCSP staple during the handshake.",
             "# TYPE certfan_node_ocsp_stapled gauge",
             "# HELP certfan_node_chain_len Number of certificates in the presented chain (leaf first).",
             "# TYPE certfan_node_chain_len gauge",
             "# HELP certfan_distinct_certs Distinct certificates served across all addresses.",
             "# TYPE certfan_distinct_certs gauge"]
    for r in reps:
        h = r["host"]
        for n in r["nodes"]:
            lab = f'host="{h}",ip="{n.addr}",serial="{n.serial}"'
            if n.ok:
                lines.append(f"certfan_node_cert_expiry_seconds{{{lab}}} {int(n.not_after.timestamp())}")
                lines.append(f"certfan_node_ocsp_stapled{{{lab}}} {1 if n.ocsp_stapled else 0}")
                lines.append(f"certfan_node_chain_len{{{lab}}} {len(n.chain_fingerprints) or 1}")
            lines.append(f"certfan_node_status{{{lab}}} {RANK[node_level(r, n.addr)]}")
        lines.append(f'certfan_distinct_certs{{host="{h}"}} {r["distinct_certs"]}')
    return "\n".join(lines) + "\n"
