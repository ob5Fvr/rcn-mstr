"""Related-domain (acquisition/infra) discovery from TLS-certificate SAN clustering.

A single certificate that covers names across several registrable domains is strong evidence those
domains belong to the same org (shared infra / acquisition / brand portfolio). Pros chase these to
widen scope. We surface each additional registrable domain as a `related_domain` finding, and with
--expand-scope we fold it into the active scope so the whole pipeline re-runs against it.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Set

from ..base import Module
from ..scope import registrable


class RelatedDomains(Module):
    name = "related"
    phase = 85           # after probe/TLS (50) and origin (55); before correlate (95)
    mode = "normal"
    final = True
    description = "Discover sibling/acquisition domains from multi-apex TLS certificates (opt. scope expansion)"

    async def run(self, ctx):
        own = set(registrable(r) for r in ctx.scope.roots)
        # cert fingerprint -> set of registrable domains it covers
        by_cert: Dict[str, Set[str]] = defaultdict(set)
        cert_meta: Dict[str, dict] = {}
        for svc in ctx.services.values():
            tls = svc.get("tls")
            if not tls or not tls.get("sans"):
                continue
            fp = tls.get("fingerprint_sha256") or svc["url"]
            cert_meta[fp] = {"cn": tls.get("common_name"), "issuer": tls.get("issuer_cn"), "url": svc["url"]}
            for san in tls["sans"]:
                san = san.lstrip("*.").lower().rstrip(".")
                if "." in san and "*" not in san:
                    by_cert[fp].add(registrable(san))
        related: Dict[str, dict] = {}
        for fp, regs in by_cert.items():
            if not (regs & own):
                continue  # only trust certs that also cover something we already own
            for r in regs - own:
                if len(r) < 4 or r in ctx.scope.roots:
                    continue
                rec = related.setdefault(r, {"domain": r, "via_certs": [], "co_domains": set()})
                rec["via_certs"].append({"fingerprint": fp[:32], **cert_meta.get(fp, {})})
                rec["co_domains"].update(regs & own)
        if not related:
            return
        expanded = []
        for r, rec in sorted(related.items()):
            conf = "high" if len(rec["via_certs"]) > 1 or len(rec["co_domains"]) > 1 else "medium"
            ctx.finding("related_domain", "info", conf, r,
                        f"Related domain {r} shares a TLS certificate with in-scope domain(s)",
                        {"domain": r, "shared_with": sorted(rec["co_domains"]),
                         "certificates": rec["via_certs"][:5]}, self.name, ["related", "scope-expansion"],
                        dedupe_key=r,
                        next_steps=[f"Confirm {r} is in program scope; if so, run rcn-mstr against it"])
            if ctx.cfg.expand_scope:
                before = len(ctx.scope.roots)
                ctx.scope.roots.append(r)
                if ctx.add_host(r, "related-cert"):
                    expanded.append(r)
                if len(ctx.scope.roots) == before:
                    pass
        if expanded:
            self.log.info("scope expanded with %d related domain(s): %s", len(expanded), ", ".join(expanded))
            ctx.stats["expanded_domains"] = expanded
