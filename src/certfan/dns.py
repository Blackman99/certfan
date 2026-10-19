"""A tiny stub DNS client (A/AAAA over UDP, TCP on truncation) so certfan can ask
specific resolvers without any third-party dependency.

Why: GeoDNS, split-horizon and per-region resolvers can hand out different address
sets. The system resolver only shows you one of them; ``--resolver`` asks several and
probes the union, remembering which resolver returned which address.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple

QTYPE = {"A": 1, "AAAA": 28}
CNAME = 5
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSError(OSError):
    pass


def parse_resolver(spec: str) -> Tuple[str, int]:
    """'1.1.1.1', '1.1.1.1:5353', '2606:4700::1111', '[2606:4700::1111]:53'."""
    s = spec.strip()
    if s.startswith("["):
        ip, _, rest = s[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else 53
    elif s.count(":") == 1:
        ip, p = s.split(":")
        port = int(p)
    else:
        ip, port = s, 53
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"--resolver expects an IP address (optionally :port), got {spec!r}") from None
    if not 0 < port < 65536:
        raise ValueError(f"--resolver port out of range in {spec!r}")
    return ip, port


def label(server: Tuple[str, int]) -> str:
    ip, port = server
    if port == 53:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def build_query(name: str, qtype: int, qid: int) -> bytes:
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1
    q = b""
    for part in name.rstrip(".").split("."):
        raw = part.encode("idna")
        if not 0 < len(raw) < 64:
            raise DNSError(f"invalid DNS name {name!r}")
        q += bytes([len(raw)]) + raw
    return hdr + q + b"\x00" + struct.pack(">HH", qtype, 1)


def _skip_name(buf: bytes, i: int) -> int:
    while True:
        if i >= len(buf):
            raise DNSError("truncated DNS response")
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def parse_response(buf: bytes, qid: int, qtype: int) -> Tuple[List[str], bool]:
    """Return (addresses of qtype, truncated). Raises DNSError on error rcodes."""
    if len(buf) < 12:
        raise DNSError("short DNS response")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    if rid != qid:
        raise DNSError("DNS response id mismatch")
    if flags & 0x0200:
        return [], True
    rcode = flags & 0x000F
    if rcode == 3:
        return [], False  # NXDOMAIN: no addresses, not a resolver failure
    if rcode:
        raise DNSError(RCODES.get(rcode, f"rcode {rcode}"))
    i = 12
    for _ in range(qd):
        i = _skip_name(buf, i) + 4
    out: List[str] = []
    for _ in range(an):
        i = _skip_name(buf, i)
        if i + 10 > len(buf):
            raise DNSError("truncated DNS response")
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        rdata = buf[i:i + rdlen]
        i += rdlen
        # The recursive resolver already followed CNAMEs; collect the final address records.
        if rtype == qtype == 1 and rdlen == 4:
            out.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == qtype == 28 and rdlen == 16:
            out.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return out, False


def _family(ip: str) -> int:
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _udp(server, pkt: bytes, timeout: float) -> bytes:
    with socket.socket(_family(server[0]), socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, server)
        return s.recvfrom(4096)[0]


def _tcp(server, pkt: bytes, timeout: float) -> bytes:
    with socket.create_connection(server, timeout=timeout) as s:
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        hdr = _recv(s, 2)
        return _recv(s, struct.unpack(">H", hdr)[0])


def _recv(s, n: int) -> bytes:
    b = b""
    while len(b) < n:
        chunk = s.recv(n - len(b))
        if not chunk:
            raise DNSError("DNS TCP connection closed early")
        b += chunk
    return b


def query(server: Tuple[str, int], name: str, rtype: str, timeout: float = 3.0) -> List[str]:
    qtype = QTYPE[rtype]
    qid = struct.unpack(">H", os.urandom(2))[0]
    pkt = build_query(name, qtype, qid)
    try:
        addrs, truncated = parse_response(_udp(server, pkt, timeout), qid, qtype)
        if truncated:
            addrs, _ = parse_response(_tcp(server, pkt, timeout), qid, qtype)
    except socket.timeout:
        raise DNSError(f"no answer from {label(server)} within {timeout:g}s") from None
    except DNSError:
        raise
    except OSError as e:
        raise DNSError(f"{label(server)}: {e.strerror or e}") from None
    return addrs


def resolve_with(servers: List[Tuple[str, int]], host: str, family: str = "any",
                 timeout: float = 3.0) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """Ask every server for A/AAAA. Returns ({ip: [resolver labels]}, {resolver: error})."""
    try:
        ipaddress.ip_address(host)
        return {host: [label(s) for s in servers]}, {}
    except ValueError:
        pass
    types = {"any": ["A", "AAAA"], "4": ["A"], "6": ["AAAA"]}[family]
    jobs = [(srv, t) for srv in servers for t in types]

    def ask(job):
        srv, t = job
        try:
            return query(srv, host, t, timeout), None
        except DNSError as e:
            return [], f"{t}: {e}"

    # All resolvers and record types in parallel: one dead resolver costs one timeout, not N.
    with ThreadPoolExecutor(max_workers=min(16, len(jobs))) as ex:
        answers = list(ex.map(ask, jobs))
    seen: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}
    for (srv, _t), (addrs, err) in zip(jobs, answers):
        lab = label(srv)
        if err:
            errors.setdefault(lab, err)
        for ip in addrs:
            who = seen.setdefault(ip, [])
            if lab not in who:
                who.append(lab)
    return seen, errors
