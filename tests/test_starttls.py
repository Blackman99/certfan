"""STARTTLS / ALPN tests. Every server here is a local fake from certfan.demo: no network."""
import json
import socket

import pytest

import certfan.probe as probe_mod
from certfan.cli import main
from certfan.demo import bundled_ca, serve, serve_starttls
from certfan.probe import probe
from certfan.report import evaluate, to_json, to_prom
from certfan.starttls import StartTLSError, upgrade
from certfan.targets import parse_targets_file

PROTOS = ["smtp", "imap", "pop3", "postgres"]
CA = bundled_ca()
SNI = "shop.example.test"


@pytest.fixture
def servers():
    stops = []

    def start(*a, **kw):
        port, stop = serve_starttls(*a, **kw)
        stops.append(stop)
        return port

    yield start
    for s in stops:
        s()


def _probe(port, proto, **kw):
    kw.setdefault("timeout", 2)
    return probe("127.0.0.1", port, SNI, cafile=CA, starttls=proto, **kw)


@pytest.mark.parametrize("proto", PROTOS)
def test_upgrade_and_compare_each_protocol(servers, proto):
    a1, a2, b = servers(proto), servers(proto), servers(proto, "b.crt", "b.key")
    nodes = [_probe(p, proto) for p in (a1, a2, b)]
    assert all(n.ok for n in nodes), [n.error for n in nodes]
    assert nodes[0].fingerprint == nodes[1].fingerprint != nodes[2].fingerprint
    assert all(n.starttls == proto for n in nodes)
    if proto != "postgres":
        assert "mx.example.test" in nodes[0].banner
    rep = evaluate(f"{SNI}:x", nodes, 7, 33, starttls=proto)
    assert rep["verdict"] == "FAIL" and rep["distinct_certs"] == 2


@pytest.mark.parametrize("proto,needle", [
    ("smtp", "does not advertise STARTTLS"),
    ("imap", "does not advertise STARTTLS"),
    ("pop3", "does not advertise STLS"),
    ("postgres", "answered 'N'"),
])
def test_not_advertised_is_a_starttls_failure(servers, proto, needle):
    n = _probe(servers(proto, mode="noadvert"), proto)
    assert not n.ok and n.error_stage == "starttls"
    assert needle in n.error
    # --allow-unreachable must not hide a node that has lost its TLS config
    rep = evaluate(SNI, [n], 7, 33, allow_unreachable=True, starttls=proto)
    assert rep["verdict"] == "FAIL"
    assert [f[0] for f in rep["findings"]] == ["FAIL"]
    assert rep["findings"][0][2].split(" failed: ")[0] in (
        "SMTP STARTTLS", "IMAP STARTTLS", "POP3 STLS", "PostgreSQL SSLRequest")


@pytest.mark.parametrize("proto,needle", [
    ("smtp", "454"), ("imap", "NO STARTTLS unavailable"), ("pop3", "-ERR STLS not available"),
])
def test_refused(servers, proto, needle):
    n = _probe(servers(proto, mode="refuse"), proto)
    assert n.error_stage == "starttls" and "refused" in n.error and needle in n.error


@pytest.mark.parametrize("proto", PROTOS)
def test_plaintext_injection_is_rejected(servers, proto):
    n = _probe(servers(proto, mode="inject"), proto)
    assert n.error_stage == "starttls"
    assert "plaintext after" in n.error


def test_silent_server_times_out_with_hint(servers):
    n = _probe(servers("smtp", mode="silent"), "smtp", timeout=0.4)
    assert not n.ok
    assert "timed out waiting for the SMTP greeting" in n.error
    assert "drop --starttls" in n.error


def test_imap_greeting_capabilities_and_preauth(servers):
    assert _probe(servers("imap", mode="greetcaps"), "imap").ok
    n = _probe(servers("imap", mode="preauth"), "imap")
    assert n.error_stage == "starttls" and "PREAUTH" in n.error


def test_pop3_without_capa_still_tries_stls(servers):
    assert _probe(servers("pop3", mode="nocapa"), "pop3").ok


def test_upgrade_rejects_oversized_line():
    a, b = socket.socketpair()
    try:
        b.sendall(b"220 " + b"x" * 5000)
        a.settimeout(1)
        with pytest.raises(StartTLSError, match="line"):
            upgrade(a, "smtp")
    finally:
        a.close()
        b.close()


def test_upgrade_reports_close():
    a, b = socket.socketpair()
    b.close()
    a.settimeout(1)
    with pytest.raises((StartTLSError, ConnectionError)):
        upgrade(a, "smtp")
    a.close()


def test_hint_when_starttls_port_probed_as_plain_tls(servers, monkeypatch):
    port = servers("smtp")
    monkeypatch.setitem(probe_mod.STARTTLS_PORTS, port, "smtp")
    n = probe("127.0.0.1", port, SNI, timeout=2, cafile=CA)
    assert not n.ok
    assert "try --starttls smtp" in n.error


# --- CLI ------------------------------------------------------------------------------------------

def _cli(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr()


def test_cli_text_and_json(servers, capsys):
    ports = [servers("smtp", name="mx1.example.test"), servers("smtp", name="mx2.example.test")]
    conn = sum([["--connect", f"127.0.0.1:{p}"] for p in ports], [])
    code, out = _cli(capsys, "check", SNI, "--starttls", "smtp", "--cafile", CA, *conn)
    assert code == 0, out.out
    assert f"{SNI}:25  2 address(es) over SMTP STARTTLS" in out.out
    assert "as mx1.example.test" in out.out
    code, out = _cli(capsys, "check", SNI, "--starttls", "smtp", "--cafile", CA,
                     "--format", "json", *conn)
    doc = json.loads(out.out)[0]
    assert doc["host"] == f"{SNI}:25" and doc["starttls"] == "smtp"
    assert doc["nodes"][0]["banner"].startswith("220 mx1.example.test")


def test_cli_explicit_port_keeps_target_name(servers, capsys):
    p = servers("imap")
    code, out = _cli(capsys, "check", f"{SNI}:{p}", "--starttls", "imap", "--cafile", CA,
                     "--connect", "127.0.0.1", "--format", "json")
    assert code == 0
    assert json.loads(out.out)[0]["host"] == f"{SNI}:{p}"


@pytest.mark.parametrize("target,proto", [("m.example:465", "smtp"), ("m.example:993", "imap"),
                                          ("m.example:995", "pop3")])
def test_cli_rejects_implicit_tls_ports(capsys, target, proto):
    with pytest.raises(SystemExit) as e:
        main(["check", target, "--starttls", proto])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "implicit TLS" in err and "usage: certfan check" in err


def test_cli_bad_alpn(capsys):
    with pytest.raises(SystemExit):
        main(["check", "x.example", "--alpn", ","])
    assert "empty ALPN list" in capsys.readouterr().err


def test_demo_starttls(capsys):
    code, out = _cli(capsys, "demo", "--starttls", "pop3")
    assert code == 0
    assert "over POP3 STLS" in out.out and "does not advertise STLS" in out.out
    assert "verdict: FAIL" in out.out


def test_targets_file_overrides(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("mx.example.com starttls=smtp\nwww.example.com alpn=h2,http/1.1 starttls=none\n")
    e = parse_targets_file(str(p))
    assert e[0] == ("mx.example.com", {"starttls": "smtp"})
    assert e[1] == ("www.example.com", {"alpn": ["h2", "http/1.1"], "starttls": "none"})
    p.write_text("mx.example.com starttls=ftp\n")
    with pytest.raises(ValueError, match="invalid starttls"):
        parse_targets_file(str(p))
    p.write_text("mx.example.com alpn=\n")
    with pytest.raises(ValueError, match="empty alpn"):
        parse_targets_file(str(p))


def test_targets_file_mixes_protocols(servers, tmp_path, capsys):
    smtp, pg = servers("smtp"), servers("postgres")
    p = tmp_path / "t.txt"
    p.write_text(f"127.0.0.1:{smtp} starttls=smtp\n127.0.0.1:{pg} starttls=postgres\n")
    code, out = _cli(capsys, "check", "-f", str(p), "--no-verify", "--format", "json")
    docs = json.loads(out.out)
    assert code == 0, out.out
    assert [d["starttls"] for d in docs] == ["smtp", "postgres"]


# --- ALPN -----------------------------------------------------------------------------------------

@pytest.fixture
def tls():
    stops = []

    def start(alpn=None):
        port, stop = serve("a.crt", "a.key", alpn=alpn)
        stops.append(stop)
        return port

    yield start
    for s in stops:
        s()


def test_alpn_agreement_and_divergence(tls):
    offer = ["h2", "http/1.1"]
    ports = [tls(["h2", "http/1.1"]), tls(["h2", "http/1.1"]), tls(["http/1.1"]), tls()]
    nodes = [probe("127.0.0.1", p, SNI, timeout=2, cafile=CA, alpn=offer) for p in ports]
    assert [n.alpn for n in nodes] == ["h2", "h2", "http/1.1", None]
    rep = evaluate(SNI, nodes[:2], 7, 33, alpn=offer)
    assert rep["verdict"] == "PASS"
    rep = evaluate(SNI, nodes, 7, 33, alpn=offer)
    assert rep["verdict"] == "WARN"
    msgs = [f[2] for f in rep["findings"]]
    assert "negotiated ALPN http/1.1 while other nodes negotiate h2" in msgs
    assert "negotiated ALPN none while other nodes negotiate h2" in msgs
    prom = to_prom([rep])
    assert 'alpn="h2"} 1' in prom and 'alpn=""} 1' in prom
    assert json.loads(to_json([rep]))[0]["alpn_offered"] == offer


def test_alpn_no_overlap_is_explained(tls):
    n = probe("127.0.0.1", tls(["h2"]), SNI, timeout=2, cafile=CA, alpn=["spdy/3"])
    # OpenSSL servers either abort with no_application_protocol or ignore ALPN; both are fine
    assert (not n.ok and "ALPN" in n.error) or (n.ok and n.alpn is None)


def test_alpn_and_starttls_together(servers):
    p = servers("smtp", alpn=["smtp"])
    n = _probe(p, "smtp", alpn=["smtp"])
    assert n.ok and n.alpn == "smtp"


def test_no_alpn_no_prom_series(tls):
    n = probe("127.0.0.1", tls(["h2"]), SNI, timeout=2, cafile=CA)
    assert n.alpn is None
    assert "certfan_node_alpn_info{" not in to_prom([evaluate(SNI, [n], 7, 33)])


def test_servers_are_threaded(servers):
    # a slow client must not block another one (the fake servers are used concurrently)
    p = servers("smtp")
    s = socket.create_connection(("127.0.0.1", p))
    try:
        assert _probe(p, "smtp").ok
    finally:
        s.close()
