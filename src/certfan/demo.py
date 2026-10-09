"""Self-contained demo: three local TLS 'nodes', one still serving last month's certificate."""
from __future__ import annotations

import os
import socket
import ssl
import threading

DATA = os.path.join(os.path.dirname(__file__), "data")


def serve(cert: str, key: str):
    """Start a TLS server on 127.0.0.1:<random>; return (port, stop)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(DATA, cert), os.path.join(DATA, key))
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
