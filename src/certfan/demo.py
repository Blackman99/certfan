"""Self-contained demo: three local TLS 'nodes', one still serving last month's certificate."""
from __future__ import annotations

import os
import socket
import ssl
import threading

DATA = os.path.join(os.path.dirname(__file__), "data")


def _server_ctx(cert: str, key: str, alpn=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(DATA, cert), os.path.join(DATA, key))
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    return ctx


def serve(cert: str, key: str, alpn=None):
    """Start a TLS server on 127.0.0.1:<random>; return (port, stop)."""
    ctx = _server_ctx(cert, key, alpn)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(2)
                with ctx.wrap_socket(conn, server_side=True) as s:
                    try:
                        s.recv(1)
                    except OSError:
                        pass
            except (ssl.SSLError, OSError):
                pass
        srv.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1], stop.set


def bundled_ca() -> str:
    """A CA bundle that trusts both demo certs (they are self-signed)."""
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd, "w") as f:
        for n in ("a.crt", "b.crt"):
            with open(os.path.join(DATA, n)) as src:
                f.write(src.read())
    return path


# --- STARTTLS nodes -------------------------------------------------------------------------------
# Tiny fake mail / database servers for `certfan demo --starttls` and the test-suite. They speak just
# enough of each protocol for a client to ask for TLS. mode:
#   ok        advertise and accept the upgrade
#   noadvert  never advertise STARTTLS / STLS (PostgreSQL: answer 'N')
#   refuse    advertise it, then refuse (SMTP 454, IMAP NO, POP3 -ERR)
#   silent    accept the TCP connection and never say anything (timeouts)
#   inject    send extra plaintext right after the go-ahead (response injection)
#   preauth   IMAP only: greet with PREAUTH
#   nocapa    POP3 only: answer -ERR to CAPA but still accept STLS
#   greetcaps IMAP only: put [CAPABILITY ...] in the greeting


def _readline(conn) -> bytes:
    out = b""
    while not out.endswith(b"\n"):
        b = conn.recv(1)  # one byte at a time: never swallow the client's ClientHello
        if not b:
            break
        out += b
    return out.strip()


def _talk_smtp(conn, mode, name):
    conn.sendall(f"220 {name} ESMTP certfan-demo\r\n".encode())
    while True:
        line = _readline(conn).upper()
        if not line:
            return False
        if line.startswith((b"EHLO", b"HELO")):
            exts = ["PIPELINING", "SIZE 10240000"] + ([] if mode == "noadvert" else ["STARTTLS"])
            exts.append("8BITMIME")
            reply = [f"250-{name}"] + [f"250-{e}" for e in exts[:-1]] + [f"250 {exts[-1]}"]
            conn.sendall(("\r\n".join(reply) + "\r\n").encode())
        elif line == b"STARTTLS":
            if mode == "refuse":
                conn.sendall(b"454 4.7.0 TLS not available due to local problem\r\n")
                continue
            extra = b"250 injected\r\n" if mode == "inject" else b""
            conn.sendall(b"220 2.0.0 Ready to start TLS\r\n" + extra)
            return True
        elif line == b"QUIT":
            conn.sendall(b"221 2.0.0 Bye\r\n")
            return False
        else:
            conn.sendall(b"502 5.5.2 Error: command not recognized\r\n")


def _talk_imap(conn, mode, name):
    caps = "IMAP4rev1 LITERAL+ " + ("" if mode == "noadvert" else "STARTTLS ") + "LOGINDISABLED"
    if mode == "preauth":
        conn.sendall(f"* PREAUTH {name} ready\r\n".encode())
    elif mode == "greetcaps":
        conn.sendall(f"* OK [CAPABILITY {caps}] {name} ready\r\n".encode())
    else:
        conn.sendall(f"* OK {name} IMAP4rev1 ready\r\n".encode())
    while True:
        line = _readline(conn).decode()
        if not line:
            return False
        tag, _, cmd = line.partition(" ")
        cmd = cmd.upper()
        if cmd == "CAPABILITY":
            conn.sendall(f"* CAPABILITY {caps}\r\n{tag} OK done\r\n".encode())
        elif cmd == "STARTTLS":
            if mode in ("refuse", "noadvert"):
                conn.sendall(f"{tag} NO STARTTLS unavailable\r\n".encode())
                continue
            extra = b"* OK injected\r\n" if mode == "inject" else b""
            conn.sendall(f"{tag} OK Begin TLS negotiation now\r\n".encode() + extra)
            return True
        else:
            conn.sendall(f"{tag} BAD unknown command\r\n".encode())


def _talk_pop3(conn, mode, name):
    conn.sendall(f"+OK {name} POP3 ready\r\n".encode())
    while True:
        line = _readline(conn).upper()
        if not line:
            return False
        if line == b"CAPA":
            if mode == "nocapa":
                conn.sendall(b"-ERR unknown command\r\n")
                continue
            caps = ["USER", "UIDL"] + ([] if mode == "noadvert" else ["STLS"])
            conn.sendall(("+OK\r\n" + "\r\n".join(caps) + "\r\n.\r\n").encode())
        elif line == b"STLS":
            if mode in ("refuse", "noadvert"):
                conn.sendall(b"-ERR STLS not available\r\n")
                continue
            extra = b"+OK injected\r\n" if mode == "inject" else b""
            conn.sendall(b"+OK Begin TLS negotiation\r\n" + extra)
            return True
        else:
            conn.sendall(b"-ERR unknown command\r\n")


def _talk_postgres(conn, mode, name):
    req = b""
    while len(req) < 8:
        b = conn.recv(8 - len(req))
        if not b:
            return False
        req += b
    if req != bytes.fromhex("0000000804d2162f"):
        return False
    if mode in ("noadvert", "refuse"):
        conn.sendall(b"N")
        return False
    conn.sendall(b"S" + (b"E" if mode == "inject" else b""))
    return True


_TALK = {"smtp": _talk_smtp, "imap": _talk_imap, "pop3": _talk_pop3, "postgres": _talk_postgres}


def serve_starttls(proto: str, cert: str = "a.crt", key: str = "a.key", mode: str = "ok",
                   name: str = "mx.example.test", alpn=None):
    """Start a fake STARTTLS server (smtp/imap/pop3/postgres) on 127.0.0.1; return (port, stop)."""
    ctx = _server_ctx(cert, key, alpn)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(0.2)
    stop = threading.Event()

    def handle(conn):
        try:
            conn.settimeout(3)
            if mode == "silent":
                stop.wait(3)
                return
            if _TALK[proto](conn, mode, name):
                with ctx.wrap_socket(conn, server_side=True) as s:
                    try:
                        s.recv(1)
                    except OSError:
                        pass
        except (ssl.SSLError, OSError, UnicodeDecodeError):
            pass
        finally:
            conn.close()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        srv.close()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1], stop.set
