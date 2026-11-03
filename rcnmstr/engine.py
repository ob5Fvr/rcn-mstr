"""Orchestrator: builds the context, runs modules by phase, drives the feedback loop."""
from __future__ import annotations

import asyncio
import logging
import os
import time
import traceback

from .base import ordered
from .context import Config, Context
from .dns.resolver import Resolver, ResolverUnavailable
from .http import make_api_session, make_probe_session
from .scope import Scope

log = logging.getLogger("rcnmstr")


def select_modules(cfg: Config, ctx: Context):
    mods = []
    wanted = set(cfg.modules) if cfg.modules else None
    for cls in ordered():
        if wanted is not None:
            if cls.name not in wanted and cls.name != "analysis":
                continue
        else:
            if not cls.default:
                continue
            if not ctx.mode_allows(cls.mode):
                continue
        if cls.name in cfg.skip:
            continue
        mods.append(cls())
    return mods


async def _run_module(ctx: Context, mod) -> None:
    t0 = time.monotonic()
    st = ctx.module_status.setdefault(mod.name, {"runs": 0, "seconds": 0.0, "errors": []})
    st["runs"] += 1
    try:
        await asyncio.wait_for(mod.run(ctx), ctx.cfg.module_timeout)
    except asyncio.TimeoutError:
        st["errors"].append(f"timeout after {ctx.cfg.module_timeout}s (round {ctx.round})")
        log.warning("module %s timed out", mod.name)
    except ResolverUnavailable:
        raise
    except Exception as e:  # noqa
        st["errors"].append(f"{type(e).__name__}: {e}")
        log.error("module %s crashed: %s\n%s", mod.name, e, traceback.format_exc())
    st["seconds"] = round(st["seconds"] + time.monotonic() - t0, 2)


async def run(cfg: Config) -> Context:
    scope = Scope.from_file(cfg.domains, cfg.scope_file, cfg.exclude_file)
    if not scope.roots:
        raise SystemExit("no valid root domain given")
    ctx = Context(cfg, scope, cfg.output)
    ctx.api = make_api_session()
    try:
        ctx.resolver = Resolver(cfg.resolvers, concurrency=cfg.dns_concurrency, health_name=cfg.health_name,
                                api_session=ctx.api, force_doh=cfg.force_doh)
        await ctx.resolver.start()
        ctx.stats["dns_mode"] = ctx.resolver.mode
        ctx.stats["dns_health"] = ctx.resolver.health_report
        ctx.probe = make_probe_session(ctx.resolver, concurrency=cfg.concurrency, timeout=cfg.timeout,
                                       proxy=cfg.proxy, **({"user_agent": cfg.user_agent} if cfg.user_agent else {}))
        for r in scope.roots:
            ctx.add_host(r, "input")
        mods = select_modules(cfg, ctx)
        log.info("modules: %s", ", ".join(m.name for m in mods))
        loop_mods = [m for m in mods if not m.final]
        final_mods = [m for m in mods if m.final]
        for rnd in range(1, max(1, cfg.max_rounds) + 1):
            ctx.round = rnd
            before = len(ctx.hosts)
            log.info("==== round %d (%d hosts known) ====", rnd, before)
            for m in loop_mods:
                if rnd > 1 and not m.loop:
                    continue
                await _run_module(ctx, m)
            new = len(ctx.hosts) - before
            log.info("round %d done: +%d hosts, %d pending", rnd, new, len(ctx.pending_hosts))
            if not ctx.pending_hosts and not ctx.web_targets_pending():
                break
        ctx.round += 1
        for m in final_mods:
            await _run_module(ctx, m)
    finally:
        try:
            from .report import write_outputs
            write_outputs(ctx)
        finally:
            ctx.close()
            if ctx.probe:
                await ctx.probe.close()
            await ctx.api.close()
            if ctx.resolver:
                await ctx.resolver.close()
    return ctx


def default_outdir(domains) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return os.path.join("rcn-out", f"{domains[0]}-{stamp}")
