import datetime as dt
import json
import ssl

from certfan.cli import main
from certfan.demo import DATA, bundled_ca, serve
from certfan.der import parse_cert
from certfan.probe import NodeResult, probe
from certfan.report import evaluate, to_prom

UTC = dt.timezone.utc


def node(fp="x", nb=(2026, 1, 1), na=(2026, 12, 1), ip="10.0.0.1", **kw):
    return NodeResult(ip=ip, port=443, ok=True, fingerprint=fp, serial=fp * 4,
                      not_before=dt.datetime(*nb, tzinfo=UTC), not_after=dt.datetime(*na, tzinfo=UTC), **kw)


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


def test_live_probe_verify():
    port, stop = serve("a.crt", "a.key")
    ca = bundled_ca()
    try:
        ok = probe("127.0.0.1", port, "shop.example.test", cafile=ca)
        assert ok.ok and not ok.verify_error and ok.subject_cn == "shop.example.test"
        bad = probe("127.0.0.1", port, "wrong.example.test", cafile=ca)
        assert bad.ok and bad.verify_error
    finally:
        stop()


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
    data = json.loads(capsys.readouterr().out)
    assert code == 2 and data[0]["distinct_certs"] == 2
    assert prom.read_text().count("certfan_node_status") >= 2


def test_demo_runs(capsys):
    assert main(["demo"]) == 0
    assert "2 distinct certificate" in capsys.readouterr().out
