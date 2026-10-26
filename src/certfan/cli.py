"""certfan command line."""
from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .probe import probe, resolve
from .report import RANK, evaluate, render_text, to_json, to_prom
from .starttls import IMPLICIT_TLS, NAMES, PROTOCOLS
from .targets import parse_targets_file

EXIT = {"PASS": 0, "WARN": 1, "FAIL": 2}


def _split(target: str, default_port: int = 443):
    """host[:port] / [v6]:port -> (host, port, port_was_given)."""
    host, port, given = target, default_port, False
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        if rest.startswith(":"):
            port, given = int(rest[1:]), True
    elif target.count(":") == 1:
        host, p = target.split(":")
        port, given = int(p), True
    return host, port, given


def _alpn(s: str):
    protos = [p.strip() for p in s.split(",") if p.strip()]
    if not protos:
        raise argparse.ArgumentTypeError("empty ALPN list (example: --alpn h2,http/1.1)")
    for p in protos:
        if len(p.encode()) > 255 or not p.isascii():
            raise argparse.ArgumentTypeError(f"invalid ALPN protocol id {p!r}")
    return protos


def _job_starttls(args, ov):
    st = ov.get("starttls", getattr(args, "starttls", None)) or ""
    return "" if st == "none" else st


def _job_alpn(args, ov):
    if "alpn" in ov:
        return ov["alpn"]
    return [p for group in (getattr(args, "alpn", None) or []) for p in group]


def _addr(s: str, default_port: int):
    if s.startswith("["):
        ip, _, rest = s[1:].partition("]")
        return ip, int(rest[1:]) if rest.startswith(":") else default_port
    if s.count(":") == 1:
        ip, p = s.split(":")
        return ip, int(p)
    return s, default_port


def _resolver(s: str):
    from .dns import parse_resolver
    try:
        return parse_resolver(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def check_target(target, args, connect=None, warn_days=None, warn_pct=None, starttls=None,
                 alpn=None):
    if starttls is None:
        starttls = _job_starttls(args, {})
    if alpn is None:
        alpn = _job_alpn(args, {})
    host, port, given = _split(target, PROTOCOLS.get(starttls, 443))
    if starttls and not given:
        # Report the port we actually used, so "mail.example.com" over SMTP and over HTTPS
        # never collide in one Prometheus textfile.
        target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    sni = args.sni or host
    wd = args.warn_days if warn_days is None else warn_days
    wp = args.warn_pct if warn_pct is None else warn_pct
    dns = None
    seen_by = {}
    if connect:
        addrs = [_addr(a, port) for a in connect]
    elif getattr(args, "resolver", None):
        from .dns import label, resolve_with
        seen_by, errors = resolve_with(args.resolver, host, args.family, args.timeout)
        dns = {"resolvers": [label(r) for r in args.resolver], "errors": errors}
        addrs = [(ip, port) for ip in seen_by]
    else:
        try:
            addrs = [(ip, port) for ip in resolve(host, port, args.family)]
        except OSError as e:
            from .probe import NodeResult
            n = NodeResult(ip=host, port=port, error=f"DNS: {e}", starttls=starttls)
            return evaluate(target, [n], wd, wp, allow_unreachable=args.allow_unreachable,
                            starttls=starttls, alpn=alpn)
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(addrs)))) as ex:
        nodes = list(ex.map(lambda a: probe(a[0], a[1], sni, args.timeout, args.cafile,
                                            not args.no_verify, starttls, alpn),
                            addrs)) if addrs else []
    for n in nodes:
        n.resolvers = list(seen_by.get(n.ip, []))
    return evaluate(target, nodes, wd, wp, allow_unreachable=args.allow_unreachable,
                    dns=dns, dns_divergence=getattr(args, "dns_divergence", "note"),
                    starttls=starttls, alpn=alpn)


def _emit(reps, args):
    if args.format == "json":
        print(to_json(reps))
    elif args.format == "prom":
        print(to_prom(reps), end="")
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        print(render_text(reps, color=color), end="")
    if args.prom_file:
        tmp = args.prom_file + ".tmp"
        with open(tmp, "w") as f:
            f.write(to_prom(reps))
        os.replace(tmp, args.prom_file)
    worst = max((r["verdict"] for r in reps), key=RANK.get, default="PASS")
    return EXIT[worst]


def _common(p):
    p.add_argument("--warn-days", type=float, default=7.0,
                   help="warn when fewer than N days remain (default 7)")
    p.add_argument("--warn-pct", type=float, default=33.0,
                   help="warn when less than N%% of the cert lifetime remains (default 33)")
    p.add_argument("--format", choices=["text", "json", "prom"], default="text")
    p.add_argument("--prom-file", help="also write Prometheus textfile metrics here (atomic)")
    p.add_argument("--timeout", type=float, default=5.0, help="per-address timeout seconds")


def _collect_jobs(args, ap):
    """Build [(target, warn_days, warn_pct, starttls, alpn), ...] from positionals and -f file."""
    entries = [(t, {}) for t in args.targets]
    if getattr(args, "targets_file", None):
        try:
            entries += parse_targets_file(args.targets_file)
        except (OSError, ValueError) as e:
            ap.error(str(e))
    if not entries:
        ap.error("provide at least one host[:port] or -f FILE")
    jobs = []
    for t, ov in entries:
        st = _job_starttls(args, ov)
        try:
            _, port, given = _split(t, PROTOCOLS.get(st, 443))
        except ValueError:
            ap.error(f"{t}: port must be a number")
        if st and given and port in IMPLICIT_TLS:
            ap.error(f"{t}: port {port} is implicit TLS ({NAMES[IMPLICIT_TLS[port]]} over TLS from the "
                     f"first byte); drop --starttls {st} for this target")
        jobs.append((t, ov.get("warn_days", args.warn_days), ov.get("warn_pct", args.warn_pct),
                     st, _job_alpn(args, ov)))
    return jobs


def main(argv=None):
    ap = argparse.ArgumentParser(prog="certfan", description="Probe every IP behind a TLS hostname "
                                 "and catch the node still serving an old or broken certificate.")
    ap.add_argument("--version", action="version", version=f"certfan {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="check one or more host[:port] targets")
    c.add_argument("targets", nargs="*", metavar="host[:port]")
    c.add_argument("-f", "--file", dest="targets_file", metavar="FILE",
                   help="read targets from FILE (one host[:port] per line; # comments; optional "
                        "warn_days=N warn_pct=N starttls=PROTO|none alpn=P1,P2 per line)")
    c.add_argument("-4", dest="family", action="store_const", const="4", default="any",
                   help="IPv4 addresses only")
    c.add_argument("-6", dest="family", action="store_const", const="6", help="IPv6 addresses only")
    c.add_argument("--connect", action="append", metavar="IP[:PORT]",
                   help="probe these addresses instead of DNS (repeatable; single target only)")
    c.add_argument("--resolver", action="append", metavar="IP[:PORT]", type=_resolver,
                   help="ask this DNS resolver instead of the system one (repeatable; addresses "
                        "from all resolvers are probed, e.g. to catch GeoDNS/split-horizon nodes)")
    c.add_argument("--dns-divergence", choices=["note", "warn", "fail"], default="note",
                   help="with 2+ --resolver: how to treat an address only some resolvers return "
                        "(default note: shown, verdict unchanged)")
    c.add_argument("--starttls", choices=sorted(PROTOCOLS), metavar="PROTO",
                   help="upgrade a plaintext connection first: smtp, imap, pop3 or postgres; the "
                        "default port becomes 25 / 143 / 110 / 5432 (for 465/993/995, which speak "
                        "TLS directly, leave this off)")
    c.add_argument("--alpn", action="append", type=_alpn, metavar="PROTO[,PROTO...]",
                   help="offer these ALPN protocols (e.g. h2,http/1.1) and warn when nodes "
                        "select different ones")
    c.add_argument("--sni", help="SNI / hostname to verify (default: the target host)")
    c.add_argument("--cafile", help="extra CA bundle to trust")
    c.add_argument("--no-verify", action="store_true", help="skip chain/hostname verification")
    c.add_argument("--allow-unreachable", action="store_true",
                   help="treat unreachable addresses as WARN instead of FAIL")
    _common(c)
    d = sub.add_parser("demo", help="run against three local nodes, one serving a stale cert")
    d.add_argument("--starttls", choices=sorted(PROTOCOLS), metavar="PROTO",
                   help="demo a mail/database fleet instead: four local smtp/imap/pop3/postgres "
                        "nodes, one with a stale cert and one that never offers STARTTLS")
    _common(d)
    args = ap.parse_args(argv)
    if args.cmd == "check":
        jobs = _collect_jobs(args, c)
        if args.connect and len(jobs) > 1:
            c.error("--connect works with a single target")
        if args.connect and args.resolver:
            c.error("--connect and --resolver are alternatives; use one")
        reps = [check_target(t, args, args.connect, warn_days=wd, warn_pct=wp, starttls=st, alpn=al)
                for t, wd, wp, st, al in jobs]
        return _emit(reps, args)
    if args.cmd == "demo":
        from .demo import bundled_ca, serve, serve_starttls
        st = args.starttls or ""
        if st:
            # four mail/db nodes: two current, one stale, one that lost its TLS config entirely
            servers = [serve_starttls(st, "a.crt", "a.key", name="mx1.example.test"),
                       serve_starttls(st, "a.crt", "a.key", name="mx2.example.test"),
                       serve_starttls(st, "b.crt", "b.key", name="mx3.example.test"),
                       serve_starttls(st, mode="noadvert", name="mx4.example.test")]
        else:
            servers = [serve("a.crt", "a.key"), serve("a.crt", "a.key"), serve("b.crt", "b.key")]
        ca = bundled_ca()
        try:
            args.sni, args.cafile, args.no_verify = "shop.example.test", ca, False
            args.family, args.allow_unreachable = "any", False
            rep = check_target("shop.example.test", args,
                               [f"127.0.0.1:{p}" for p, _ in servers], starttls=st, alpn=[])
            # pretend these are three load-balancer nodes on 443
            code = _emit([rep], args)
        finally:
            for _, stop in servers:
                stop()
            os.unlink(ca)
        sys.stdout.flush()
        print("(demo: exit code would be %d; returning 0)" % code, file=sys.stderr)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
