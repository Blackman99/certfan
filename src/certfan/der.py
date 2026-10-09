"""Tiny DER reader: just enough X.509 to pull serial, validity, subject CN, issuer CN and SANs (stdlib only)."""
from __future__ import annotations

import datetime as _dt


def _tlv(buf: bytes, i: int):
    tag = buf[i]
    i += 1
    ln = buf[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, buf[i:i + ln], i + ln


def _children(buf: bytes):
    i, out = 0, []
    while i < len(buf):
        tag, val, i = _tlv(buf, i)
        out.append((tag, val))
    return out


def _time(tag: int, val: bytes) -> _dt.datetime:
    s = val.decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSS
        yy = int(s[:2])
        s = ("19" if yy >= 50 else "20") + s
    return _dt.datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=_dt.timezone.utc)


_CN = bytes.fromhex("550403")
_SAN = bytes.fromhex("551d11")


def _cn(name: bytes) -> str:
    for _, rdn in _children(name):
        for _, atv in _children(rdn):
            parts = _children(atv)
            if len(parts) >= 2 and parts[0][1] == _CN:
                return parts[1][1].decode("utf-8", "replace")
    return ""


def parse_cert(der: bytes) -> dict:
    _, cert, _ = _tlv(der, 0)
    tbs = _children(_children(cert)[0][1])
    idx = 1 if tbs[0][0] == 0xA0 else 0
    serial = tbs[idx][1].lstrip(b"\x00").hex() or "0"
    issuer = tbs[idx + 2][1]
    validity = _children(tbs[idx + 3][1])
    subject = tbs[idx + 4][1]
    sans: list[str] = []
    for tag, val in tbs[idx + 6:]:
        if tag == 0xA3:
            for _, ext in _children(_children(val)[0][1]):
                parts = _children(ext)
                if parts and parts[0][1] == _SAN:
                    for t, v in _children(_children(parts[-1][1])[0][1]):
                        if t == 0x82:
                            sans.append(v.decode("ascii", "replace"))
                        elif t == 0x87:
                            import ipaddress
                            sans.append(str(ipaddress.ip_address(v)))
    return {
        "serial": serial,
        "not_before": _time(*validity[0]),
        "not_after": _time(*validity[1]),
        "subject_cn": _cn(subject),
        "issuer_cn": _cn(issuer),
        "sans": sans,
    }
