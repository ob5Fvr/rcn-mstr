"""Origin-IP discovery for CDN-fronted hosts: gather candidates, verify by Host-header request + body simhash."""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Dict, List, Optional, Set

from ..base import Module, gather_limited
from ..http import fetch
from ..util import hamming, html_title, is_public_ip, simhash


class OriginIP(Module):
    name = "origin"
    phase = 55
    mode = "normal"
    final = True
    description = "Find real origin IPs behind CDNs by testing candidate IPs with the correct Host header + SNI"

    async def run(self, ctx):
        fronted = [h for h, r in ctx.hosts.items()
                   if r.get("cdn") and r.get("dns") and r["dns"].get("resolved")]
        if not fronted:
            return
        candidates = self._candidates(ctx)
        self.log.info("origin: %d fronted hosts, %d candidate IPs", len(fronted), len(candidates))
        if not candidates:
            return
        for host in fronted:
            await self._check_host(ctx, host, candidates)

    def _candidates(self, ctx) -> List[str]:
        cands: Set[str] = set()
        # non-CDN IPs of any sibling host
        for ip, rec in ctx.ips.items():
            if is_public_ip(ip) and not rec.get("cdn"):
                cands.add(ip)
        # SPF ip4 ranges (small ones expanded)
        for ips in ctx.stats.get("spf_ips", {}).values():
            for entry in ips:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    if net.num_addresses <= 256:
                        cands.update(str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address]))
                except ValueError:
                    pass
        # MX host IPs
        for z in ctx.zones.values():
            for mx in z.get("MX", []):
                rec = ctx.hosts.get(mx["exchange"])
                if rec and rec.get("dns"):
                    cands.update(ip for ip in rec["dns"]["a"] if is_public_ip(ip))
        # InternetDB-discovered IPs already in ctx.ips are included above
        return sorted(c for c in cands if not self._is_cdn_ip(ctx, c))

    def _is_cdn_ip(self, ctx, ip):
        from ..data.cdn_ranges import cdn_for_ip
        rec = ctx.ips.get(ip)
        return bool((rec and rec.get("cdn")) or cdn_for_ip(ip))

    async def _baseline(self, ctx, host) -> Optional[dict]:
        for scheme in ("https", "http"):
            r = await fetch(ctx.probe, f"{scheme}://{host}/", timeout=ctx.cfg.timeout, max_bytes=500000,
                            allow_redirects=False)
            if r:
                return {"scheme": scheme, "status": r.status, "simhash": simhash(r.text),
                        "title": html_title(r.text), "len": len(r.body)}
        return None

    async def _check_host(self, ctx, host, candidates):
        base = await self._baseline(ctx, host)
        if not base:
            return
        results = await gather_limited(
            [self._try(ctx, host, ip, base) for ip in candidates], ctx.cfg.concurrency)
        verified = [r for r in results if isinstance(r, dict) and r.get("verified")]
        if verified:
            for v in verified:
                ctx.finding("origin_ip_exposure", "high", "high", host,
                            f"Likely origin IP {v['ip']} behind {ctx.hosts[host].get('cdn')}",
                            {"ip": v["ip"], "cdn": ctx.hosts[host].get("cdn"), "status": v["status"],
                             "simhash_distance": v["distance"], "title": v["title"], "evidence": v["why"]},
                            self.name, ["origin", "cdn-bypass"],
                            next_steps=[f"curl -k -H 'Host: {host}' https://{v['ip']}/ and access directly"])
            ctx.hosts[host]["origin_ips"] = [v["ip"] for v in verified]

    async def _try(self, ctx, host, ip, base) -> Optional[dict]:
        scheme = base["scheme"]
        port = 443 if scheme == "https" else 80
        url = f"{scheme}://{ip}:{port}/" if port not in (80, 443) else f"{scheme}://{ip}/"
        r = await fetch(ctx.probe, url, headers={"Host": host}, server_hostname=host if scheme == "https" else None,
                        timeout=ctx.cfg.timeout, max_bytes=500000, allow_redirects=False)
        if not r:
            return None
        dist = hamming(base["simhash"], simhash(r.text))
        title = html_title(r.text)
        why = []
        if base["status"] == r.status:
            why.append("same status")
        if dist <= 8:
            why.append(f"simhash dist {dist}")
        if title and title == base["title"]:
            why.append("same title")
        verified = (dist <= 8) or (title and title == base["title"] and base["status"] == r.status and r.status < 500)
        return {"ip": ip, "status": r.status, "distance": dist, "title": title, "verified": bool(verified),
                "why": why}
