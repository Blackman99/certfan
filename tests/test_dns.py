import json
import socket
import struct
import threading

import pytest

from certfan import dns
from certfan.cli import main
from certfan.demo import bundled_ca, serve
from certfan.probe import NodeResult
from certfan.report import evaluate, render_text, to_json, to_prom


def _answer(query: bytes, addrs, rcode=0, tc=False, cname=False):
    qid = query[:2]
    # question section = everything after the 12-byte header
    question = query[12:]
    qtype = struct.unpack(">H", question[-4:-2])[0]
    recs = b""
    count = 0
    if cname:  # a CNAME record first, pointing elsewhere (resolver already followed it)
        target = b"\x04edge\x03cdn\x00"
        recs += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(target)) + target
        count += 1
    for ip in addrs:
        fam, t = (socket.AF_INET6, 28) if ":" in ip else (socket.AF_INET, 1)
        if t != qtype:
            continue
        raw = socket.inet_pton(fam, ip)
        recs += b"\xc0\x0c" + struct.pack(">HHIH", t, 1, 60, len(raw)) + raw
        count += 1
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    return qid + struct.pack(">HHHHH", flags, 1, count, 0, 0) + question + recs


class FakeResolver:
    """UDP (+TCP) stub resolver on 127.0.0.1 with a fixed answer."""

    def __init__(self, addrs, rcode=0, truncate_udp=False, cname=False, silent=False):
        self.addrs, self.rcode, self.tc, self.cname, self.silent = addrs, rcode, truncate_udp, cname, silent
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(4)
        self.tcp_hits = 0
        for fn in (self._udp, self._tcp):
            threading.Thread(target=fn, daemon=True).start()

    @property
    def spec(self):
        return f"127.0.0.1:{self.port}"

    def _udp(self):
        while True:
            try:
                q, peer = self.udp.recvfrom(512)
            except OSError:
                return
            if not self.silent:
                self.udp.sendto(_answer(q, [] if self.tc else self.addrs, self.rcode, self.tc, self.cname), peer)

    def _tcp(self):
        while True:
            try:
                c, _ = self.tcp.accept()
            except OSError:
                return
            with c:
                n = struct.unpack(">H", c.recv(2))[0]
                q = c.recv(n)
                self.tcp_hits += 1
                a = _answer(q, self.addrs, self.rcode, False, self.cname)
                c.sendall(struct.pack(">H", len(a)) + a)

    def close(self):
        self.udp.close()
        self.tcp.close()


@pytest.fixture
def resolvers():
    made = []

    def make(*a, **kw):
        r = FakeResolver(*a, **kw)
        made.append(r)
        return r
    yield make
    for r in made:
        r.close()


def test_parse_resolver():
    assert dns.parse_resolver("1.1.1.1") == ("1.1.1.1", 53)
    assert dns.parse_resolver("1.1.1.1:5353") == ("1.1.1.1", 5353)
    assert dns.parse_resolver("2606:4700::1111") == ("2606:4700::1111", 53)
    assert dns.parse_resolver("[2606:4700::1111]:853") == ("2606:4700::1111", 853)
    with pytest.raises(ValueError):
        dns.parse_resolver("dns.google")


def test_query_a_and_aaaa_through_cname(resolvers):
    r = resolvers(["192.0.2.10", "192.0.2.11", "2001:db8::1"], cname=True)
    srv = ("127.0.0.1", r.port)
    assert dns.query(srv, "shop.example.test", "A") == ["192.0.2.10", "192.0.2.11"]
    assert dns.query(srv, "shop.example.test", "AAAA") == ["2001:db8::1"]


def test_truncated_udp_falls_back_to_tcp(resolvers):
    r = resolvers(["192.0.2.20"], truncate_udp=True)
    assert dns.query(("127.0.0.1", r.port), "shop.example.test", "A") == ["192.0.2.20"]
    assert r.tcp_hits == 1


def test_nxdomain_is_empty_servfail_is_error(resolvers):
    nx = resolvers([], rcode=3)
    assert dns.query(("127.0.0.1", nx.port), "nope.example.test", "A") == []
    sf = resolvers([], rcode=2)
    with pytest.raises(dns.DNSError, match="SERVFAIL"):
        dns.query(("127.0.0.1", sf.port), "shop.example.test", "A")


def test_resolve_with_union_and_attribution(resolvers):
    eu = resolvers(["192.0.2.1", "192.0.2.2"])
    us = resolvers(["192.0.2.2", "192.0.2.3"])
    dead = resolvers([], silent=True)
    servers = [("127.0.0.1", eu.port), ("127.0.0.1", us.port), ("127.0.0.1", dead.port)]
    seen, errors = dns.resolve_with(servers, "shop.example.test", "4", timeout=0.3)
    assert list(seen) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert seen["192.0.2.2"] == [eu.spec, us.spec]
    assert seen["192.0.2.3"] == [us.spec]
    assert list(errors) == [dead.spec] and "no answer" in errors[dead.spec]


def _n(ip, by):
    import datetime as dt
    utc = dt.timezone.utc
    return NodeResult(ip=ip, port=443, ok=True, fingerprint="f", serial="s" * 16, issuer_cn="CA",
                      not_before=dt.datetime(2026, 1, 1, tzinfo=utc),
                      not_after=dt.datetime(2026, 12, 1, tzinfo=utc), resolvers=by,
                      chain_fingerprints=["f"])


def test_divergence_note_warn_fail():
    import datetime as dt
    now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
    nodes = [_n("192.0.2.1", ["eu", "us"]), _n("192.0.2.3", ["us"])]
    d = {"resolvers": ["eu", "us"], "errors": {}}
    note = evaluate("h", nodes, now=now, dns=d)
    assert note["verdict"] == "PASS" and note["dns"]["divergent"] is True
    text = render_text([note])
    assert "from 2 resolvers (answers differ)" in text and "via us" in text
    assert "certfan_dns_divergent{host=\"h\"} 1" in to_prom([note])
    assert json.loads(to_json([note]))[0]["dns"]["divergent"] is True
    warn = evaluate("h", nodes, now=now, dns=d, dns_divergence="warn")
    assert warn["verdict"] == "WARN"
    assert [f[1] for f in warn["findings"]] == ["192.0.2.3"]
    assert "not returned by resolver eu" in warn["findings"][0][2]
    assert evaluate("h", nodes, now=now, dns=d, dns_divergence="fail")["verdict"] == "FAIL"


def test_failed_resolver_warns_without_tainting_nodes():
    import datetime as dt
    now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
    nodes = [_n("192.0.2.1", ["eu"])]
    r = evaluate("h", nodes, now=now, dns={"resolvers": ["eu", "us"], "errors": {"us": "A: timeout"}})
    assert r["verdict"] == "WARN" and r["dns"]["divergent"] is False
    assert r["findings"] == [("WARN", "resolver us", "lookup failed: A: timeout")]
    assert "PASS" in render_text([r]).splitlines()[1]


def test_cli_resolver_end_to_end(capsys, resolvers):
    port, stop = serve("a.crt", "a.key")
    ca = bundled_ca()
    a = resolvers(["127.0.0.1"])
    b = resolvers(["127.0.0.1"])
    try:
        code = main(["check", f"shop.example.test:{port}", "--sni", "shop.example.test", "--cafile", ca,
                     "--resolver", a.spec, "--resolver", b.spec, "-4", "--format", "json"])
    finally:
        stop()
    out = json.loads(capsys.readouterr().out)[0]
    assert code == 0, out
    assert out["dns"] == {"resolvers": [a.spec, b.spec], "errors": {}, "divergent": False}
    assert out["nodes"][0]["resolvers"] == [a.spec, b.spec]


def test_cli_resolver_rejects_hostname_and_connect(capsys):
    with pytest.raises(SystemExit):
        main(["check", "x.test", "--resolver", "dns.google"])
    with pytest.raises(SystemExit):
        main(["check", "x.test", "--resolver", "1.1.1.1", "--connect", "10.0.0.1"])
