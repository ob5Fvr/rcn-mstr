"""Command-line interface for rcn-mstr."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from typing import List

from . import __version__
from .base import ordered
from .context import Config
from .engine import default_outdir, run


def _load_config_file(path):
    """Load a config file (JSON, or simple key: value / key = value lines). Returns a flat dict."""
    if not path or not os.path.exists(path):
        return {}
    text = open(path, encoding="utf-8").read()
    if path.endswith(".json") or text.lstrip().startswith("{"):
        return json.loads(text)
    cfg = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in (":", "="):
            if sep in line:
                k, v = line.split(sep, 1)
                k, v = k.strip(), v.strip().strip('"\'')
                if v.lower() in ("true", "false"):
                    v = v.lower() == "true"
                elif v.isdigit():
                    v = int(v)
                elif "," in v:
                    v = [x.strip() for x in v.split(",") if x.strip()]
                cfg[k.replace("-", "_")] = v
                break
    return cfg


def _load_keys(path):
    keys = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            if path.endswith(".json"):
                keys = {k.lower(): v for k, v in json.load(fh).items()}
            else:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        keys[k.strip().lower()] = v.strip().strip('"\'')
    return keys


def build_parser():
    p = argparse.ArgumentParser(prog="rcn-mstr", description="Modular async recon framework (AI-ingestible output)")
    p.add_argument("domains", nargs="*", help="root domain(s), e.g. example.com")
    p.add_argument("-o", "--output", help="output directory (default rcn-out/<domain>-<ts>)")
    p.add_argument("-m", "--mode", choices=["passive", "normal", "deep"], default="normal",
                   help="passive=no active probing; normal=probe+content+js; deep=+portscan+origin+wide")
    p.add_argument("--modules", help="comma list: run ONLY these modules (analysis always runs)")
    p.add_argument("--skip", default="", help="comma list of modules to skip")
    p.add_argument("--list-modules", action="store_true", help="list modules and exit")
    p.add_argument("-r", "--resolvers", help="file or comma list of resolver IPs")
    p.add_argument("--health-name", default="google.com", help="name used for resolver health checks")
    p.add_argument("--force-doh", action="store_true", help="skip UDP, use DNS-over-HTTPS only")
    p.add_argument("-w", "--wordlist", help="subdomain brute-force wordlist (SecLists-sized ok)")
    p.add_argument("--no-brute", action="store_true", help="disable brute force")
    p.add_argument("--max-rounds", type=int, default=4, help="feedback-loop rounds (default 4)")
    p.add_argument("--max-permutations", type=int, default=20000)
    p.add_argument("-c", "--concurrency", type=int, default=80, help="HTTP concurrency")
    p.add_argument("--dns-concurrency", type=int, default=400)
    p.add_argument("-t", "--timeout", type=float, default=10.0, help="per-request timeout seconds")
    p.add_argument("--proxy", help="HTTP proxy for probe traffic (e.g. http://127.0.0.1:8080)")
    p.add_argument("--rate", type=float, default=0.0, help="max HTTP requests/sec PER HOST (0=unlimited)")
    p.add_argument("--per-host", type=int, default=10, help="max concurrent connections per host")
    p.add_argument("--top-ports", type=int, default=100, help="deep mode: number of top ports to scan")
    p.add_argument("--ports", help="deep mode: explicit comma port list (overrides --top-ports)")
    p.add_argument("--http-ports", default="80,443", help="ports probed for HTTP in all modes")
    p.add_argument("--archive-limit", type=int, default=50000)
    p.add_argument("--no-archive-recheck", action="store_true")
    p.add_argument("--max-buckets", type=int, default=600)
    p.add_argument("--allow-private", action="store_true", help="probe/scan RFC1918 IPs")
    p.add_argument("--expand-scope", action="store_true",
                   help="auto-add related domains discovered via shared TLS certs to the active scope")
    p.add_argument("--nuclei", action="store_true",
                   help="run nuclei against live URLs if the binary is on PATH (deep mode)")
    p.add_argument("--favicon-db", help="custom favicon-hash -> product JSON db")
    p.add_argument("--no-tools", action="store_true", help="do not call external binaries (subfinder/amass)")
    p.add_argument("--user-agent")
    p.add_argument("-s", "--scope", help="scope file (one host/pattern per line, ! prefix excludes)")
    p.add_argument("-x", "--exclude", help="exclude file")
    p.add_argument("-k", "--keys", help="API keys file (KEY=value or json)")
    p.add_argument("--config", help="config file (json or key: value lines) providing CLI defaults")
    p.add_argument("--update-fingerprints", action="store_true", help="refresh takeover fingerprints and exit")
    p.add_argument("--self-test", action="store_true",
                   help="run the full pipeline against an in-process mock internet (no egress needed)")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                   help="compare two run output directories and print attack-surface drift")
    p.add_argument("--json", action="store_true", help="with --diff: emit JSON instead of a summary")
    p.add_argument("--html", metavar="RUN_DIR",
                   help="(re)generate report.html from an existing run output directory and exit")
    p.add_argument("--query", nargs=2, metavar=("RUN_DIR", "QUERY"),
                   help="run a store query against a run dir, e.g. --query out \"select hosts where cdn is null\"")
    p.add_argument("--agent-plan", metavar="RUN_DIR",
                   help="print the ranked attack-hypothesis agent plan (JSON) from a run dir and exit")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--version", action="version", version=f"rcn-mstr {__version__}")
    return p


def _csv(val):
    return [x.strip() for x in val.split(",") if x.strip()] if val else []


async def _update_fp():
    from .http import make_api_session
    from .modules.takeover import update_fingerprints
    s = make_api_session()
    try:
        n = await update_fingerprints(s)
        print(f"updated fingerprints.json ({n} entries)")
    finally:
        await s.close()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    # config-file values become defaults for any option the user did not pass explicitly
    if getattr(args, "config", None):
        fileconf = _load_config_file(args.config)
        explicit = set()
        for tok in (argv if argv is not None else sys.argv[1:]):
            if tok.startswith("--"):
                explicit.add(tok[2:].split("=")[0].replace("-", "_"))
            elif tok.startswith("-") and len(tok) == 2:
                explicit.add(tok)
        for k, v in fileconf.items():
            k = k.replace("-", "_")
            if k in ("keys", "api_keys"):
                continue
            if hasattr(args, k) and k not in explicit:
                setattr(args, k, v)
    level = logging.WARNING if args.quiet else (logging.DEBUG if args.verbose >= 2 else logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname).1s %(name)s: %(message)s",
                        datefmt="%H:%M:%S", stream=sys.stderr)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    if args.list_modules:
        for cls in ordered():
            print(f"  {cls.name:14s} phase={cls.phase:<3d} mode={cls.mode:<7s} "
                  f"{'loop ' if cls.loop else ''}{'final ' if cls.final else ''} {cls.description}")
        return 0
    if args.update_fingerprints:
        asyncio.run(_update_fp())
        return 0
    if args.self_test:
        from .selftest import run_self_test
        return asyncio.run(run_self_test(args.output or "rcn-selftest-out"))
    if args.html:
        from .htmlreport import write_html
        print(write_html(args.html))
        return 0
    if args.query:
        from .store import ReconStore
        rows = ReconStore.load(args.query[0]).query(args.query[1])
        print(json.dumps(rows, indent=1, default=str))
        return 0
    if args.agent_plan:
        from .store import ReconStore
        print(json.dumps(ReconStore.load(args.agent_plan).agent_plan(top=50), indent=1, default=str))
        return 0
    if args.diff:
        from .diff import diff_runs, summarize
        d = diff_runs(args.diff[0], args.diff[1])
        if args.json:
            print(json.dumps(d, indent=1, default=str))
        else:
            print(summarize(d))
        return 0 if not d["has_changes"] else 10  # exit 10 => changes detected (useful for cron/CI)
    if not args.domains:
        build_parser().error("at least one domain is required (or use --list-modules/--update-fingerprints)")

    keys = _load_keys(args.keys)
    if getattr(args, "favicon_db", None):
        from .modules.probe import favicon_db as _fdb
        import rcnmstr.modules.probe as _pm
        _pm._FAVDB = _fdb(args.favicon_db)
    resolvers = None
    if args.resolvers:
        resolvers = [l.strip() for l in open(args.resolvers)] if os.path.exists(args.resolvers) else _csv(args.resolvers)
        resolvers = [r for r in resolvers if r and not r.startswith("#")]

    cfg = Config(
        domains=args.domains,
        output=args.output or default_outdir(args.domains),
        mode=args.mode,
        modules=_csv(args.modules) or None,
        skip=_csv(args.skip),
        resolvers=resolvers,
        health_name=args.health_name,
        force_doh=args.force_doh,
        wordlist=args.wordlist,
        brute=not args.no_brute,
        max_rounds=args.max_rounds,
        max_permutations=args.max_permutations,
        concurrency=args.concurrency,
        dns_concurrency=args.dns_concurrency,
        timeout=args.timeout,
        proxy=args.proxy,
        keys=keys,
        top_ports=args.top_ports,
        scan_ports=[int(x) for x in _csv(args.ports)] or None,
        http_ports=[int(x) for x in _csv(args.http_ports)] or [80, 443],
        archive_limit=args.archive_limit,
        recheck_archive=not args.no_archive_recheck,
        max_buckets=args.max_buckets,
        allow_private=args.allow_private,
        expand_scope=args.expand_scope,
        nuclei=args.nuclei,
        rate=args.rate,
        per_host=args.per_host,
        tools=not args.no_tools,
        user_agent=args.user_agent,
        scope_file=args.scope,
        exclude_file=args.exclude,
    )
    from .dns.resolver import ResolverUnavailable
    try:
        ctx = asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except ResolverUnavailable as e:
        print("\n[FATAL] DNS is unusable in this environment - aborting instead of emitting garbage.\n",
              file=sys.stderr)
        print(str(e), file=sys.stderr)
        print("\nFixes: pass working resolvers with -r, or --force-doh with reachable DoH, "
              "or run where UDP/53 egress is allowed.", file=sys.stderr)
        return 3
    except SystemExit as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    s = ctx.stats.get("summary", {})
    c = s.get("counts", {})
    print(f"\n=== rcn-mstr done: {', '.join(ctx.scope.roots)} ===", file=sys.stderr)
    print(f"hosts={c.get('hosts_total',0)} live={c.get('hosts_live',0)} ips={c.get('ips',0)} "
          f"services={c.get('services',0)} findings={c.get('findings',0)}", file=sys.stderr)
    print(f"severity: {s.get('findings_by_severity', {})}", file=sys.stderr)
    print(f"output -> {ctx.outdir}/  (start at index.json)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
