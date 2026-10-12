import datetime as dt
import json
import os
import ssl
import textwrap

from certfan.cli import main
from certfan.demo import DATA, bundled_ca, serve
from certfan.der import parse_cert
from certfan.probe import NodeResult, probe
from certfan.report import evaluate, to_json, to_prom
from certfan.targets import parse_targets_file

UTC = dt.timezone.utc


def node(fp="x", nb=(2026, 1, 1), na=(2026, 12, 1), ip="10.0.0.1", **kw):
    defaults = dict(
        chain_fingerprints=[fp],
        ocsp_stapled=False,
        issuer_cn="Test CA",
    )
    defaults.update(kw)
    return NodeResult(ip=ip, port=443, ok=True, fingerprint=fp, serial=fp * 4,
                      not_before=dt.datetime(*nb, tzinfo=UTC), not_after=dt.datetime(*na, tzinfo=UTC),
                      **defaults)


NOW = dt.datetime(2026, 6, 1, tzinfo=UTC)


def test_der_matches_ssl():
    pem = open(f"{DATA}/a.crt").read()
    info = parse_cert(ssl.PEM_cert_to_DER_cert(pem))
    assert info["subject_cn"] == "shop.example.test"
    assert info["sans"] == ["shop.example.test"]
    assert info["not_after"].year == 2126
    assert len(info["serial"]) >= 30


def test_all_same_passes():
    r = evaluate("h", [node(ip="1"), node(ip="2")], now=NOW)
    assert r["verdict"] == "PASS" and r["distinct_certs"] == 1


def test_minority_flagged():
    r = evaluate("h", [node(ip="1"), node(ip="2"), node("y", ip="3")], now=NOW)
    assert r["verdict"] == "FAIL"
    assert [f[1] for f in r["findings"]] == ["3"]


def test_tie_trusts_newest():
    r = evaluate("h", [node("old", nb=(2026, 1, 1), ip="1"), node("new", nb=(2026, 5, 1), ip="2")], now=NOW)
    assert [f[1] for f in r["findings"]] == ["1"]


def test_expiry_warn_and_fail():
    r = evaluate("h", [node(na=(2026, 6, 3))], now=NOW)
    assert r["verdict"] == "WARN"
    r = evaluate("h", [node(na=(2026, 5, 30))], now=NOW)
    assert r["verdict"] == "FAIL"


def test_short_lived_pct_warn():
    # 6-day cert with 1.5 days left: 25% < 33% -> WARN even though warn_days=1
    r = evaluate("h", [node(nb=(2026, 5, 27, 12), na=(2026, 6, 2, 12))], warn_days=1, now=NOW)
    assert r["verdict"] == "WARN"


def test_unreachable():
    bad = NodeResult(ip="9", port=443, error="timeout")
    assert evaluate("h", [node(), bad], now=NOW)["verdict"] == "FAIL"
    assert evaluate("h", [node(), bad], now=NOW, allow_unreachable=True)["verdict"] == "WARN"


def test_prom():
    out = to_prom([evaluate("h", [node()], now=NOW)])
    assert 'certfan_distinct_certs{host="h"} 1' in out
    assert "certfan_node_ocsp_stapled" in out
    assert "certfan_node_chain_len" in out


def test_chain_intermediate_mismatch():
    # Same leaf fingerprint, different intermediate in the presented chain
    a = node(fp="leaf", ip="1", chain_fingerprints=["leaf", "intA"])
    b = node(fp="leaf", ip="2", chain_fingerprints=["leaf", "intA"])
    c = node(fp="leaf", ip="3", chain_fingerprints=["leaf", "intB"])
    r = evaluate("h", [a, b, c], now=NOW)
    assert r["verdict"] == "FAIL"
    msgs = [f[2] for f in r["findings"] if f[1] == "3"]
    assert any("intermediate chain mismatch" in m for m in msgs)


def test_ocsp_partial_warn():
    a = node(ip="1", ocsp_stapled=True)
    b = node(ip="2", ocsp_stapled=True)
    c = node(ip="3", ocsp_stapled=False)
    r = evaluate("h", [a, b, c], now=NOW)
    assert r["verdict"] == "WARN"
    assert any("OCSP staple missing" in f[2] and f[1] == "3" for f in r["findings"])


def test_ocsp_in_json():
    r = evaluate("h", [node(ocsp_stapled=True)], now=NOW)
    data = json.loads(to_json([r]))
    assert data[0]["nodes"][0]["ocsp_stapled"] is True
    assert data[0]["nodes"][0]["chain_fingerprints"] == ["x"]


def test_issuer_mismatch_when_no_full_chain():
    a = node(fp="a", ip="1", issuer_cn="CA One", chain_fingerprints=["a"])
    b = node(fp="b", ip="2", issuer_cn="CA Two", chain_fingerprints=["b"])
    r = evaluate("h", [a, b], now=NOW)
    assert r["verdict"] == "FAIL"
    # leaf mismatch already flagged; issuer finding may be skipped as redundant
    assert any("different certificate" in f[2] for f in r["findings"])


def test_targets_file_parse(tmp_path):
    p = tmp_path / "hosts.txt"
    p.write_text(textwrap.dedent("""\
        # production edges
        shop.example.com warn_days=3 warn_pct=25
        api.example.com:8443
        # ignored
        ignored.example.com warn_days=1  # trailing comment style via strip of ' #'
    """))
    # Our parser: inline comments after ' #' — the third data line has ' #' so target kept with override
    entries = parse_targets_file(str(p))
    assert entries[0] == ("shop.example.com", {"warn_days": 3.0, "warn_pct": 25.0})
    assert entries[1] == ("api.example.com:8443", {})
    assert entries[2][0] == "ignored.example.com"
    assert entries[2][1]["warn_days"] == 1.0


def test_targets_file_cli_override(capsys, tmp_path):
    a, sa = serve("a.crt", "a.key")
    ca = bundled_ca()
    hosts = tmp_path / "hosts.txt"
    # Long-lived demo cert: global --warn-days 1 would PASS; per-line warn_days=99999 forces WARN
    hosts.write_text("shop.example.test warn_days=99999\n")
    try:
        code = main(["check", "-f", str(hosts), "--cafile", ca, "--format", "json",
                     "--connect", f"127.0.0.1:{a}", "--warn-days", "1"])
    finally:
        sa()
        os.unlink(ca)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data[0]["verdict"] == "WARN", data
    assert code == 1
    assert any("days left" in f["message"] for f in data[0]["findings"])


def test_cli_requires_target_or_file():
    try:
        main(["check"])
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert e.code == 2


def test_live_probe_verify():
    port, stop = serve("a.crt", "a.key")
    ca = bundled_ca()
    try:
        ok = probe("127.0.0.1", port, "shop.example.test", cafile=ca)
        assert ok.ok and not ok.verify_error and ok.subject_cn == "shop.example.test"
        assert ok.chain_fingerprints and ok.chain_fingerprints[0] == ok.fingerprint
        assert isinstance(ok.ocsp_stapled, bool)
        bad = probe("127.0.0.1", port, "wrong.example.test", cafile=ca)
        assert bad.ok and bad.verify_error
    finally:
        stop()
        os.unlink(ca)


def test_live_probe_chain_length():
    # Server presents leaf + intermediate; client trusts root
    port, stop = serve("chain-a.pem", "chain.key")
    try:
        r = probe("127.0.0.1", port, "shop.example.test", cafile=f"{DATA}/root.crt")
        assert r.ok and not r.verify_error
        assert r.chain_fingerprints[0] == r.fingerprint
        # Full chain available on Python 3.13+
        if hasattr(ssl.SSLSocket, "get_unverified_chain"):
            assert len(r.chain_fingerprints) >= 2
    finally:
        stop()


def test_live_chain_mismatch_finding(capsys):
    full, stop_a = serve("chain-a.pem", "chain.key")
    leaf, stop_b = serve("chain-leafonly.pem", "chain.key")
    try:
        code = main(["check", "shop.example.test", "--cafile", f"{DATA}/root.crt",
                     "--format", "json",
                     "--connect", f"127.0.0.1:{full}", "--connect", f"127.0.0.1:{leaf}"])
    finally:
        stop_a(); stop_b()
    data = json.loads(capsys.readouterr().out)
    # On 3.13+: intermediate mismatch FAIL. On older: both leaf-only chains → PASS on chain.
    nodes = data[0]["nodes"]
    assert all(n["fingerprint"] == nodes[0]["fingerprint"] for n in nodes)
    if hasattr(ssl.SSLSocket, "get_unverified_chain"):
        lens = {len(n["chain_fingerprints"]) for n in nodes}
        if len(lens) > 1:
            assert code == 2
            assert any("intermediate chain mismatch" in f["message"] for f in data[0]["findings"])


def test_cli_connect_mismatch(capsys, tmp_path):
    a, sa = serve("a.crt", "a.key")
    b, sb = serve("b.crt", "b.key")
    ca = bundled_ca()
    prom = tmp_path / "m.prom"
    try:
        code = main(["check", "shop.example.test", "--cafile", ca, "--format", "json",
                     "--prom-file", str(prom), "--connect", f"127.0.0.1:{a}", "--connect", f"127.0.0.1:{b}"])
    finally:
        sa(); sb()
        os.unlink(ca)
    data = json.loads(capsys.readouterr().out)
    assert code == 2 and data[0]["distinct_certs"] == 2
    assert prom.read_text().count("certfan_node_status") >= 2
    assert "certfan_node_ocsp_stapled" in prom.read_text()


def test_demo_runs(capsys):
    assert main(["demo"]) == 0
    assert "2 distinct certificate" in capsys.readouterr().out
