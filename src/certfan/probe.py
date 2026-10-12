"""Resolve every address for a hostname and fetch the certificate each one serves."""
from __future__ import annotations

import datetime as _dt
import hashlib
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

from .der import parse_cert


@dataclass
class NodeResult:
    ip: str
    port: int
    ok: bool = False
    error: str = ""
    verify_error: str = ""
    fingerprint: str = ""
    serial: str = ""
    subject_cn: str = ""
    issuer_cn: str = ""
    sans: list = field(default_factory=list)
    not_before: Optional[_dt.datetime] = None
    not_after: Optional[_dt.datetime] = None
    tls_version: str = ""
    ms: float = 0.0
    chain_fingerprints: list = field(default_factory=list)  # SHA-256 hex, leaf first
    ocsp_stapled: bool = False

    @property
    def addr(self) -> str:
        if self.port == 443:
            return self.ip
        return f"[{self.ip}]:{self.port}" if ":" in self.ip else f"{self.ip}:{self.port}"

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        for k in ("not_before", "not_after"):
            d[k] = d[k].isoformat() if d[k] else None
        return d


def resolve(host: str, port: int, family: str = "any") -> list[str]:
    fam = {"any": socket.AF_UNSPEC, "4": socket.AF_INET, "6": socket.AF_INET6}[family]
    seen: list[str] = []
    for info in socket.getaddrinfo(host, port, fam, socket.SOCK_STREAM):
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def _der_from_chain_item(cert) -> Optional[bytes]:
    if isinstance(cert, (bytes, bytearray)):
        return bytes(cert)
    if hasattr(cert, "public_bytes"):
        try:
            import _ssl
            return cert.public_bytes(_ssl.ENCODING_DER)
        except Exception:
            try:
                return cert.public_bytes()
            except Exception:
                return None
    return None


def _peer_chain_ders(sock, leaf_der: Optional[bytes]) -> list[bytes]:
    """Presented chain as DER bytes (leaf first). Full chain needs Python 3.13+."""
    candidates = []
    if hasattr(sock, "get_unverified_chain"):
        candidates.append(sock.get_unverified_chain)
    sslobj = getattr(sock, "_sslobj", None)
    if sslobj is not None and hasattr(sslobj, "get_unverified_chain"):
        candidates.append(sslobj.get_unverified_chain)
    for get in candidates:
        try:
            chain = get()
        except Exception:
            continue
        if not chain:
            continue
        out: list[bytes] = []
        for item in chain:
            der = _der_from_chain_item(item)
            if der:
                out.append(der)
        if out:
            return out
    return [leaf_der] if leaf_der else []


def _handshake(ip: str, port: int, sni: str, timeout: float, ctx: ssl.SSLContext):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as raw:
        raw.settimeout(timeout)
        raw.connect((ip, port))
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            der = s.getpeercert(binary_form=True)
            version = s.version()
            chain = _peer_chain_ders(s, der)
            ocsp = getattr(s, "ocsp_response", None)
            return der, version, chain, bool(ocsp)


def probe(ip: str, port: int, sni: str, timeout: float = 5.0,
          cafile: Optional[str] = None, verify: bool = True) -> NodeResult:
    r = NodeResult(ip=ip, port=port)
    t0 = time.perf_counter()
    der = None
    chain_ders: list[bytes] = []
    ocsp = False
    if verify:
        ctx = ssl.create_default_context(cafile=cafile)
        try:
            der, r.tls_version, chain_ders, ocsp = _handshake(ip, port, sni, timeout, ctx)
        except ssl.SSLCertVerificationError as e:
            r.verify_error = e.verify_message or str(e)
        except ssl.SSLError as e:
            r.verify_error = str(e)
        except OSError as e:
            r.error = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
            r.ms = (time.perf_counter() - t0) * 1000
            return r
    if der is None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            der, r.tls_version, chain_ders, ocsp = _handshake(ip, port, sni, timeout, ctx)
        except OSError as e:
            r.error = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
            r.ms = (time.perf_counter() - t0) * 1000
            return r
    r.ms = (time.perf_counter() - t0) * 1000
    r.fingerprint = hashlib.sha256(der).hexdigest()
    if not chain_ders:
        chain_ders = [der]
    r.chain_fingerprints = [hashlib.sha256(c).hexdigest() for c in chain_ders]
    r.ocsp_stapled = ocsp
    info = parse_cert(der)
    r.serial = info["serial"]
    r.subject_cn = info["subject_cn"]
    r.issuer_cn = info["issuer_cn"]
    r.sans = info["sans"]
    r.not_before = info["not_before"]
    r.not_after = info["not_after"]
    r.ok = True
    return r
