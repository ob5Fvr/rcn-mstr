"""Network intelligence: ASN/prefix/org via Team Cymru, CDN/WAF classification, Shodan InternetDB, PTR, RDAP."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
from typing import Dict, List, Optional

from ..base import Module, gather_limited
from ..data.cdn_ranges import cdn_for_ip
from ..http import api_get
from ..util import is_public_ip

DATA = os.path.join(os.path.dirname(__file__), "..", "data")

# ASN org-name substrings -> CDN/WAF vendor
CDN_ASN = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly", "amazon": "AWS/CloudFront",
    "cloudfront": "AWS/CloudFront", "google": "Google", "microsoft": "Azure", "azure": "Azure",
    "incapsula": "Imperva", "imperva": "Imperva", "sucuri": "Sucuri", "stackpath": "StackPath",
    "highwinds": "StackPath", "limelight": "Limelight", "edgecast": "Edgecast/Verizon", "verizon": "Edgecast",
    "f://": "", "bunny": "BunnyCDN", "cdn77": "CDN77", "keycdn": "KeyCDN", "gcore": "G-Core",
    "section.io": "Section", "netlify": "Netlify", "vercel": "Vercel", "ovh": "OVH", "digitalocean": "DigitalOcean",
}
# CNAME / header patterns -> vendor
CDN_CNAME = {
    r"\.cloudflare\.net$|\.cloudflare\.com$": "Cloudflare", r"\.akamai(edge|ized)?\.net$|\.akamaihd\.net$|edgekey\.net$|edgesuite\.net$": "Akamai",
    r"\.fastly\.net$|fastlylb\.net$": "Fastly", r"cloudfront\.net$": "AWS/CloudFront", r"\.azureedge\.net$|\.azurefd\.net$|trafficmanager\.net$": "Azure",
    r"incapdns\.net$|incapsula": "Imperva", r"sucuri\.net$": "Sucuri", r"\.edgecastcdn\.net$": "Edgecast",
    r"\.b-cdn\.net$": "BunnyCDN", r"\.cdn77\.(net|org)$": "CDN77", r"\.googleusercontent\.com$|ghs\.google": "Google",
    r"\.netlify\.app$": "Netlify", r"\.vercel-dns\.com$|\.vercel\.app$": "Vercel",
}
CDN_HEADER = {
    "server": {"cloudflare": "Cloudflare", "akamaighost": "Akamai", "ecacc": "Akamai", "awselb": "AWS/ELB",
               "sucuri": "Sucuri", "bigip": "F5 BIG-IP"},
    "via": {"varnish": "Varnish/Fastly", "cloudfront": "AWS/CloudFront", "1.1 google": "Google"},
    "x-cache": {"cloudfront": "AWS/CloudFront"}, "x-served-by": {"cache": "Fastly"},
    "x-cdn": {"incapsula": "Imperva"}, "x-iinfo": {"": "Imperva"}, "x-sucuri-id": {"": "Sucuri"},
    "cf-ray": {"": "Cloudflare"}, "x-amz-cf-id": {"": "AWS/CloudFront"}, "x-azure-ref": {"": "Azure"},
    "x-akamai-transformed": {"": "Akamai"}, "fly-request-id": {"": "Fly.io"},
}


async def cymru_lookup(ctx, ip: str) -> Optional[dict]:
    """Team Cymru IP-to-ASN mapping over DNS TXT."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        rev = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    ans = ctx.resolver and await ctx.resolver.query(rev, "TXT")
    if not ans or not ans.values("TXT"):
        return None
    # "13335 | 104.16.0.0/12 | US | arin | 2010-07-14"
    parts = [p.strip() for p in ans.values("TXT")[0].split("|")]
    if len(parts) < 3:
        return None
    asn = parts[0].split()[0]
    res = {"asn": asn, "prefix": parts[1], "country": parts[2], "registry": parts[3] if len(parts) > 3 else None}
    a2 = await ctx.resolver.query(f"AS{asn}.asn.cymru.com", "TXT")
    if a2.values("TXT"):
        ap = [p.strip() for p in a2.values("TXT")[0].split("|")]
        res["as_name"] = ap[-1] if ap else None
    return res


def classify_cdn_cname(chain: List[str]) -> Optional[str]:
    for c in chain:
        for pat, vendor in CDN_CNAME.items():
            if re.search(pat, c):
                return vendor
    return None


def classify_cdn_headers(headers: Dict[str, str]) -> Optional[str]:
    for h, mapping in CDN_HEADER.items():
        if h in headers:
            val = headers[h].lower()
            for needle, vendor in mapping.items():
                if needle == "" or needle in val:
                    return vendor
    return None


def classify_cdn_asn(as_name: Optional[str]) -> Optional[str]:
    if not as_name:
        return None
    low = as_name.lower()
    for needle, vendor in CDN_ASN.items():
        if needle and needle in low:
            return vendor
    return None


class NetIntel(Module):
    name = "netintel"
    phase = 40
    mode = "passive"
    loop = True
    description = "ASN/prefix/org (Team Cymru), CDN/WAF classification, PTR, Shodan InternetDB, RDAP"

    async def run(self, ctx):
        ips = [ip for ip in ctx.ips if ip not in self.done and is_public_ip(ip)]
        for ip in ips:
            self.done.add(ip)
        await gather_limited([self._ip(ctx, ip) for ip in ips], 40)
        # CDN classification per host from CNAME chains
        for h, rec in ctx.hosts.items():
            info = rec.get("dns")
            if not info:
                continue
            vendor = classify_cdn_cname(info.get("cname") or [])
            if not vendor:
                vendors = {ctx.ips[ip]["cdn"] for ip in info["a"] if ip in ctx.ips and ctx.ips[ip]["cdn"]}
                vendor = next(iter(vendors), None)
            if vendor:
                rec["cdn"] = vendor
                ctx.tag_host(h, "cdn")
        # RDAP for apexes (once)
        for root in ctx.scope.roots:
            if ("rdap:" + root) not in self.done:
                self.done.add("rdap:" + root)
                await self._rdap(ctx, root)

    async def _ip(self, ctx, ip):
        rec = ctx.ip_rec(ip)
        cymru, ptr, idb = await asyncio.gather(
            cymru_lookup(ctx, ip), ctx.resolver.ptr(ip),
            api_get(ctx.api, f"https://internetdb.shodan.io/{ip}", retries=1))
        if cymru:
            rec.update(cymru)
            rec["cdn"] = classify_cdn_asn(cymru.get("as_name"))
        # CIDR-range classification is authoritative even when Cymru is unavailable/misnamed
        range_cdn = cdn_for_ip(ip)
        if range_cdn:
            rec["cdn"] = rec.get("cdn") or range_cdn
            rec["cdn_range"] = range_cdn
        rec["ptr"] = ptr
        for name in ptr:
            ctx.add_host(name, "ptr")
        if isinstance(idb, dict) and (idb.get("ports") or idb.get("hostnames")):
            rec["internetdb"] = {"ports": idb.get("ports", []), "cpes": idb.get("cpes", []),
                                 "vulns": idb.get("vulns", []), "hostnames": idb.get("hostnames", []),
                                 "tags": idb.get("tags", [])}
            for name in idb.get("hostnames", []):
                ctx.add_host(name, "internetdb")
            for p in idb.get("ports", []):
                if p not in rec["ports"]:
                    rec["ports"].append(p)
            if idb.get("vulns"):
                ctx.finding("known_vulns", "medium", "low", ip,
                            f"Shodan InternetDB lists {len(idb['vulns'])} CVE(s) for {ip}",
                            {"vulns": idb["vulns"][:50], "cpes": idb.get("cpes", []), "ports": idb.get("ports"),
                             "hostnames": idb.get("hostnames", [])[:10]}, self.name, ["cve", "shodan"],
                            next_steps=["Confirm the CVEs by version/banner; InternetDB is advisory only"])
        ctx.emit("ip", rec)

    async def _rdap(self, ctx, domain):
        data = await api_get(ctx.api, f"https://rdap.org/domain/{domain}", retries=2)
        if not isinstance(data, dict):
            return
        out = {"domain": domain, "handle": data.get("handle"), "status": data.get("status", []),
               "events": [{e.get("eventAction"): e.get("eventDate")} for e in data.get("events", [])],
               "nameservers": [n.get("ldhName", "").lower() for n in data.get("nameservers", [])],
               "entities": []}
        for ent in data.get("entities", []):
            vcard = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
            fields = {v[0]: v[3] for v in vcard if len(v) > 3}
            out["entities"].append({"roles": ent.get("roles", []), "fn": fields.get("fn"),
                                    "email": fields.get("email"), "org": fields.get("org")})
        for ev in data.get("events", []):
            if ev.get("eventAction") == "expiration":
                out["expiration"] = ev.get("eventDate")
        ctx.emit("rdap", out)


class RipeStat(Module):
    name = "ripestat"
    phase = 41
    mode = "normal"
    final = True
    description = "RIPEstat: announced prefixes for ASNs that look org-owned (not CDN/cloud)"

    async def run(self, ctx):
        asns: Dict[str, dict] = {}
        for ip, rec in ctx.ips.items():
            if rec.get("asn") and not rec.get("cdn"):
                asns.setdefault(rec["asn"], rec)
        # heuristic: only ASNs whose name shares an org keyword, to avoid dumping cloud ranges
        kws = ctx.scope.keywords()
        for asn, rec in asns.items():
            name = (rec.get("as_name") or "").lower()
            looks_owned = any(k in name for k in kws) or (ctx.cfg.mode == "deep")
            if not looks_owned:
                continue
            data = await api_get(ctx.api, "https://stat.ripe.net/data/announced-prefixes/data.json",
                                 params={"resource": f"AS{asn}"}, retries=2)
            prefixes = [p["prefix"] for p in ((data or {}).get("data") or {}).get("prefixes", [])]
            if prefixes:
                ctx.emit("asn_prefixes", {"asn": asn, "as_name": rec.get("as_name"), "prefixes": prefixes})
                ctx.finding("asn_ownership", "info", "medium", f"AS{asn}",
                            f"AS{asn} ({rec.get('as_name')}) announces {len(prefixes)} prefix(es)",
                            {"prefixes": prefixes[:200]}, self.name, ["asn", "netblock"],
                            next_steps=["Scan org-owned ranges for additional assets (deep mode)"])
