"""Origin-IP discovery for CDN-fronted hosts: gather candidates, verify by Host-header request + body simhash."""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Dict, List, Optional, Set

from ..base import Module, gather_limited
from ..http import api_get, fetch
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
        candidates = set(self._candidates(ctx))
        candidates |= await self._api_candidates(ctx)
        candidates = sorted(c for c in candidates if not self._is_cdn_ip(ctx, c))
        self.log.info("origin: %d fronted hosts, %d candidate IPs", len(fronted), len(candidates))
        if not candidates:
            return
        for host in fronted:
            await self._check_host(ctx, host, candidates)

    async def _api_candidates(self, ctx) -> Set[str]:
        """Key-gated: Shodan favicon-hash search + Censys cert-name search surface likely origin IPs."""
        out: Set[str] = set()
        # Shodan: search by favicon hash of each probed service (http.favicon.hash:<mmh3>)
        shodan_key = ctx.key("shodan_key")
        if shodan_key:
            hashes = {s["favicon_mmh3"] for s in ctx.services.values() if s.get("favicon_mmh3")}
            for fh in list(hashes)[:5]:
                data = await api_get(ctx.api, "https://api.shodan.io/shodan/host/search",
                                     params={"key": shodan_key, "query": f"http.favicon.hash:{fh}"}, retries=1)
                for m in (data or {}).get("matches", []):
                    if m.get("ip_str"):
                        out.add(m["ip_str"])
        # Censys: search certs covering the apex to find hosts presenting them
        cid, csec = ctx.key("censys_id"), ctx.key("censys_secret")
        if cid and csec:
            import base64 as _b64
            auth = _b64.b64encode(f"{cid}:{csec}".encode()).decode()
            for root in ctx.scope.roots[:3]:
                data = await api_get(
                    ctx.api, "https://search.censys.io/api/v2/hosts/search",
                    params={"q": f"services.tls.certificates.leaf_data.names: {root}", "per_page": 50},
                    headers={"Authorization": f"Basic {auth}"}, retries=1)
                for h in ((data or {}).get("result") or {}).get("hits", []):
                    if h.get("ip"):
                        out.add(h["ip"])
        return {ip for ip in out if is_public_ip(ip)}

    def _candidates(self, ctx) -> List[str]:
        from ..util import is_private_ip
        cands: Set[str] = set()
        allow_priv = getattr(ctx.cfg, "allow_private", False)

        def usable(ip):
            return is_public_ip(ip) or (allow_priv and (is_private_ip(ip) or ip.startswith("127.")))
        # non-CDN IPs of any sibling host
        for ip, rec in ctx.ips.items():
            if usable(ip) and not rec.get("cdn"):
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

    def _service_bases(self, ctx, host):
        """(scheme, port) pairs actually observed for this host, best (https) first; fall back to 443/80."""
        bases = []
        for svc in ctx.services.values():
            if svc.get("host") == host and svc.get("status"):
                bases.append((svc["scheme"], svc["port"]))
        if not bases:
            bases = [("https", 443), ("http", 80)]
        return sorted(set(bases), key=lambda sp: sp[0] != "https")

    def _url(self, scheme, hostip, port):
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            return f"{scheme}://{hostip}/"
        return f"{scheme}://{hostip}:{port}/"

    async def _baseline(self, ctx, host) -> Optional[dict]:
        for scheme, port in self._service_bases(ctx, host):
            r = await fetch(ctx.probe, self._url(scheme, host, port), timeout=ctx.cfg.timeout,
                            max_bytes=500000, allow_redirects=False)
            if r:
                return {"scheme": scheme, "port": port, "status": r.status, "simhash": simhash(r.text),
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
        port = base.get("port", 443 if scheme == "https" else 80)
        url = self._url(scheme, ip, port)
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
