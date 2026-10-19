"""certfan command line."""
from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .probe import probe, resolve
from .report import RANK, evaluate, render_text, to_json, to_prom
from .targets import parse_targets_file

EXIT = {"PASS": 0, "WARN": 1, "FAIL": 2}


def _split(target: str):
    host, port = target, 443
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else 443
    elif target.count(":") == 1:
        host, p = target.split(":")
        port = int(p)
    return host, port


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


def check_target(target, args, connect=None, warn_days=None, warn_pct=None):
    host, port = _split(target)
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
            n = NodeResult(ip=host, port=port, error=f"DNS: {e}")
            return evaluate(target, [n], wd, wp, allow_unreachable=args.allow_unreachable)
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(addrs)))) as ex:
        nodes = list(ex.map(lambda a: probe(a[0], a[1], sni, args.timeout, args.cafile,
                                            not args.no_verify), addrs)) if addrs else []
    for n in nodes:
        n.resolvers = list(seen_by.get(n.ip, []))
    return evaluate(target, nodes, wd, wp, allow_unreachable=args.allow_unreachable,
                    dns=dns, dns_divergence=getattr(args, "dns_divergence", "note"))


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
    """Build [(target, warn_days, warn_pct), ...] from positionals and optional -f file."""
    jobs = []
    for t in args.targets:
        jobs.append((t, args.warn_days, args.warn_pct))
    if getattr(args, "targets_file", None):
        try:
            entries = parse_targets_file(args.targets_file)
        except (OSError, ValueError) as e:
            ap.error(str(e))
        for t, ov in entries:
            jobs.append((t, ov.get("warn_days", args.warn_days), ov.get("warn_pct", args.warn_pct)))
    if not jobs:
        ap.error("provide at least one host[:port] or -f FILE")
    return jobs


def main(argv=None):
    ap = argparse.ArgumentParser(prog="certfan", description="Probe every IP behind a TLS hostname "
                                 "and catch the node still serving an old or broken certificate.")
    ap.add_argument("--version", action="version", version=f"certfan {__version__}")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="check one or more host[:port] targets")
    c.add_argument("targets", nargs="*", metavar="host[:port]")
    c.add_argument("-f", "--file", dest="targets_file", metavar="FILE",
                   help="read targets from FILE (one host[:port] per line; # comments; "
                        "optional warn_days=N warn_pct=N per line)")
    c.add_argument("-4", dest="family", action="store_const", const="4", default="any")
    c.add_argument("-6", dest="family", action="store_const", const="6")
    c.add_argument("--connect", action="append", metavar="IP[:PORT]",
                   help="probe these addresses instead of DNS (repeatable; single target only)")
    c.add_argument("--resolver", action="append", metavar="IP[:PORT]", type=_resolver,
                   help="ask this DNS resolver instead of the system one (repeatable; addresses "
                        "from all resolvers are probed, e.g. to catch GeoDNS/split-horizon nodes)")
    c.add_argument("--dns-divergence", choices=["note", "warn", "fail"], default="note",
                   help="with 2+ --resolver: how to treat an address only some resolvers return "
                        "(default note: shown, verdict unchanged)")
    c.add_argument("--sni", help="SNI / hostname to verify (default: the target host)")
    c.add_argument("--cafile", help="extra CA bundle to trust")
    c.add_argument("--no-verify", action="store_true", help="skip chain/hostname verification")
    c.add_argument("--allow-unreachable", action="store_true",
                   help="treat unreachable addresses as WARN instead of FAIL")
    _common(c)
    d = sub.add_parser("demo", help="run against three local nodes, one serving a stale cert")
    _common(d)
    args = ap.parse_args(argv)
    if args.cmd == "check":
        jobs = _collect_jobs(args, ap)
        if args.connect and len(jobs) > 1:
            ap.error("--connect works with a single target")
        if args.connect and args.resolver:
            ap.error("--connect and --resolver are alternatives; use one")
        reps = [check_target(t, args, args.connect, warn_days=wd, warn_pct=wp)
                for t, wd, wp in jobs]
        return _emit(reps, args)
    if args.cmd == "demo":
        from .demo import bundled_ca, serve
        servers = [serve("a.crt", "a.key"), serve("a.crt", "a.key"), serve("b.crt", "b.key")]
        ca = bundled_ca()
        try:
            args.sni, args.cafile, args.no_verify = "shop.example.test", ca, False
            args.family, args.allow_unreachable = "any", False
            rep = check_target("shop.example.test", args,
                               [f"127.0.0.1:{p}" for p, _ in servers])
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
