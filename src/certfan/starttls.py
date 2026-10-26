"""Plaintext preambles that upgrade a connection to TLS (STARTTLS / SSLRequest).

Each upgrade speaks just enough of the protocol to ask for TLS on a fresh connection, then hands the raw
socket back for the TLS handshake. Nothing is sent after the upgrade: no AUTH, no login, no mail.
"""
from __future__ import annotations

import socket
import struct

PROTOCOLS = {"smtp": 25, "imap": 143, "pop3": 110, "postgres": 5432}
# Ports that speak TLS from the first byte; STARTTLS there would wait forever for a plaintext greeting.
IMPLICIT_TLS = {465: "smtp", 993: "imap", 995: "pop3"}
# Ports where a plain TLS ClientHello is almost certainly the wrong thing to send.
STARTTLS_PORTS = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3", 5432: "postgres"}
NAMES = {"smtp": "SMTP", "imap": "IMAP", "pop3": "POP3", "postgres": "PostgreSQL"}
# What the upgrade step is called in each protocol (for messages).
LABELS = {"smtp": "SMTP STARTTLS", "imap": "IMAP STARTTLS", "pop3": "POP3 STLS",
          "postgres": "PostgreSQL SSLRequest"}

_MAX_LINE = 4096
_MAX_LINES = 256
_PG_SSLREQUEST = struct.pack("!II", 8, 80877103)


class StartTLSError(Exception):
    """The server answered, but would not (or could not safely) switch to TLS."""

    def __init__(self, message: str, banner: str = ""):
        super().__init__(message)
        self.banner = banner


def _short(text: str, n: int = 120) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


class _Lines:
    """Minimal CRLF line reader over a raw socket that remembers anything read past the last line."""

    def __init__(self, sock: socket.socket, proto: str):
        self.sock, self.proto, self.buf, self.count = sock, proto, b"", 0

    def readline(self, waiting_for: str) -> str:
        while b"\n" not in self.buf:
            if len(self.buf) > _MAX_LINE:
                raise StartTLSError(f"{NAMES[self.proto]} line longer than {_MAX_LINE} bytes "
                                    f"while waiting for {waiting_for}")
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                raise TimeoutError(f"timed out waiting for {waiting_for}") from None
            if not chunk:
                raise ConnectionError(f"server closed the connection while we waited for {waiting_for}")
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        self.count += 1
        if self.count > _MAX_LINES:
            raise StartTLSError(f"too many {NAMES[self.proto]} response lines before {waiting_for}")
        return line.rstrip(b"\r").decode("utf-8", "replace")

    def send(self, line: str) -> None:
        self.sock.sendall(line.encode("ascii") + b"\r\n")

    def assert_drained(self, reply: str) -> None:
        # Bytes after the "go ahead" reply would be read as plaintext *before* TLS (the STARTTLS
        # response-injection class of bugs). Never start TLS on a stream like that.
        if self.buf:
            raise StartTLSError(f"server sent {len(self.buf)} byte(s) of plaintext after its STARTTLS "
                                f"reply ({_short(reply, 60)!r}); refusing to start TLS on that stream")


def _smtp_reply(r: _Lines, waiting_for: str):
    lines = []
    while True:
        line = r.readline(waiting_for)
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            break
    code = lines[-1][:3]
    if not code.isdigit():
        raise StartTLSError(f"not an SMTP server? got {_short(lines[-1], 60)!r} while waiting for {waiting_for}")
    return int(code), lines


def _ehlo_name(sock: socket.socket) -> str:
    """RFC 5321 address literal for our side of the connection (no DNS lookup, no hostname leak)."""
    try:
        ip = sock.getsockname()[0]
    except OSError:
        return "[127.0.0.1]"
    return f"[IPv6:{ip}]" if ":" in ip else f"[{ip}]"


def _smtp(sock: socket.socket) -> str:
    r = _Lines(sock, "smtp")
    code, lines = _smtp_reply(r, "the SMTP greeting (if this port speaks TLS directly, drop --starttls)")
    banner = _short(lines[0])
    if code != 220:
        raise StartTLSError(f"SMTP server refused the session: {_short(' / '.join(lines))}", banner)
    r.send(f"EHLO {_ehlo_name(sock)}")
    code, lines = _smtp_reply(r, "the EHLO reply")
    if code != 250:
        raise StartTLSError(f"SMTP server rejected EHLO: {_short(' / '.join(lines))}", banner)
    exts = [ln[4:].split()[0].upper() for ln in lines[1:] if len(ln) > 4 and ln[4:].split()]
    if "STARTTLS" not in exts:
        offered = " ".join(exts) or "nothing"
        raise StartTLSError(f"server does not advertise STARTTLS (EHLO offered: {_short(offered, 80)})",
                            banner)
    r.send("STARTTLS")
    code, lines = _smtp_reply(r, "the STARTTLS reply")
    if code != 220:
        raise StartTLSError(f"server refused STARTTLS: {_short(' / '.join(lines))}", banner)
    r.assert_drained(lines[-1])
    return banner


def _imap_tagged(r: _Lines, tag: str, waiting_for: str):
    untagged = []
    while True:
        line = r.readline(waiting_for)
        if line.startswith(tag + " "):
            return line[len(tag) + 1:], untagged
        untagged.append(line)


def _imap_caps(text: str) -> set:
    up = text.upper()
    if "CAPABILITY" not in up:
        return set()
    rest = up.split("CAPABILITY", 1)[1]
    return set(rest.replace("]", " ").split())


def _imap(sock: socket.socket) -> str:
    r = _Lines(sock, "imap")
    greet = r.readline("the IMAP greeting (if this port speaks TLS directly, drop --starttls)")
    banner = _short(greet)
    up = greet.upper()
    if up.startswith("* PREAUTH"):
        raise StartTLSError("IMAP server pre-authenticated the session (PREAUTH); STARTTLS is not "
                            "allowed after that", banner)
    if not up.startswith("* OK"):
        raise StartTLSError(f"IMAP server refused the session: {banner}", banner)
    caps = _imap_caps(greet) if "[CAPABILITY" in up else None
    if caps is None:
        r.send("cf1 CAPABILITY")
        status, untagged = _imap_tagged(r, "cf1", "the CAPABILITY reply")
        caps = set()
        for line in untagged:
            if line.upper().startswith("* CAPABILITY"):
                caps |= _imap_caps(line)
    if "STARTTLS" not in caps:
        offered = " ".join(sorted(caps)) or "nothing"
        raise StartTLSError(f"server does not advertise STARTTLS (CAPABILITY: {_short(offered, 80)})",
                            banner)
    r.send("cf2 STARTTLS")
    status, _ = _imap_tagged(r, "cf2", "the STARTTLS reply")
    if not status.upper().startswith("OK"):
        raise StartTLSError(f"server refused STARTTLS: {_short(status)}", banner)
    r.assert_drained(status)
    return banner


def _pop3(sock: socket.socket) -> str:
    r = _Lines(sock, "pop3")
    greet = r.readline("the POP3 greeting (if this port speaks TLS directly, drop --starttls)")
    banner = _short(greet)
    if not greet.startswith("+OK"):
        raise StartTLSError(f"POP3 server refused the session: {banner}", banner)
    r.send("CAPA")
    first = r.readline("the CAPA reply")
    if first.startswith("+OK"):
        caps = []
        while True:
            line = r.readline("the end of the CAPA list")
            if line == ".":
                break
            caps.append(line.split()[0].upper() if line.split() else "")
        if "STLS" not in caps:
            offered = " ".join(c for c in caps if c) or "nothing"
            raise StartTLSError(f"server does not advertise STLS (CAPA: {_short(offered, 80)})", banner)
    # -ERR to CAPA: an old server without RFC 2449; asking for STLS directly is the only way to know.
    r.send("STLS")
    reply = r.readline("the STLS reply")
    if not reply.startswith("+OK"):
        raise StartTLSError(f"server refused STLS: {_short(reply)}", banner)
    r.assert_drained(reply)
    return banner


def _assert_quiet(sock: socket.socket, reply: str) -> None:
    """Fail if bytes are already waiting after a one-byte go-ahead (PostgreSQL's 'S')."""
    timeout = sock.gettimeout()
    try:
        sock.setblocking(False)
        extra = sock.recv(4096, socket.MSG_PEEK)
    except (BlockingIOError, InterruptedError):
        extra = b""
    except OSError:
        extra = b""
    finally:
        sock.settimeout(timeout)
    if extra:
        raise StartTLSError(f"server sent {len(extra)} byte(s) of plaintext after its SSLRequest "
                            f"answer ({reply}); refusing to start TLS on that stream")


def _postgres(sock: socket.socket) -> str:
    sock.sendall(_PG_SSLREQUEST)
    try:
        b = sock.recv(1)  # exactly one byte: anything after 'S' belongs to the TLS handshake
    except socket.timeout:
        raise TimeoutError("timed out waiting for the PostgreSQL SSLRequest answer") from None
    if not b:
        raise ConnectionError("server closed the connection after the PostgreSQL SSLRequest")
    if b == b"S":
        _assert_quiet(sock, "'S'")
        return ""
    if b == b"N":
        raise StartTLSError("server does not accept SSL (answered 'N' to SSLRequest; ssl = off?)")
    if b == b"E":
        raise StartTLSError("server answered SSLRequest with an error (very old PostgreSQL, or not "
                            "PostgreSQL)")
    raise StartTLSError(f"not a PostgreSQL server? answered {b!r} to SSLRequest")


_UPGRADES = {"smtp": _smtp, "imap": _imap, "pop3": _pop3, "postgres": _postgres}


def upgrade(sock: socket.socket, proto: str) -> str:
    """Run the plaintext preamble on a connected socket; return the server banner ('' if none).

    Raises StartTLSError when the server refuses, TimeoutError / ConnectionError when it goes quiet.
    """
    return _UPGRADES[proto](sock)
