"""Passive subdomain enumeration from free and key-gated sources (+ optional subfinder/amass)."""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Callable, Dict, Iterable, List

from ..base import Module
from ..http import api_get
from ..scope import clean_host

# ----------------------------------------------------------------------------- parsers (pure, unit-tested)


def parse_crtsh(data) -> List[str]:
    out = []
    for row in data or []:
        for field in ("name_value", "common_name"):
            for n in str(row.get(field, "")).split("\n"):
                out.append(n)
    return out


def parse_certspotter(data) -> List[str]:
    return [n for row in data or [] for n in row.get("dns_names", [])]


def parse_hackertarget(text: str) -> List[tuple]:
    if not text or text.startswith("error") or "API count exceeded" in text:
        return []
    out = []
    for line in text.splitlines():
        parts = line.strip().split(",")
        if parts and parts[0]:
            out.append((parts[0], parts[1] if len(parts) > 1 else None))
    return out


def parse_otx(data) -> List[tuple]:
    return [(r.get("hostname", ""), r.get("address")) for r in (data or {}).get("passive_dns", [])]


def parse_urlscan(data) -> List[str]:
    out = []
    for r in (data or {}).get("results", []):
        for k in ("page", "task"):
            d = r.get(k) or {}
            if d.get("domain"):
                out.append(d["domain"])
            if d.get("url"):
                out.append(d["url"])
    return out


def parse_list(data) -> List[str]:
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, dict):
        for k in ("subdomains", "hosts", "data", "results"):
            if isinstance(data.get(k), list):
                return [x if isinstance(x, str) else (x.get("id") or x.get("hostname") or "") for x in data[k]]
    return []


def labels_to_hosts(labels: Iterable[str], domain: str) -> List[str]:
    out = []
    for l in labels:
        l = str(l).strip().strip(".").lower()
        if not l:
            continue
        out.append(l if (l == domain or l.endswith("." + domain)) else f"{l}.{domain}")
    return out


# ----------------------------------------------------------------------------- sources


class _Src:
    name = ""
    key: str = ""        # env/config key name; empty = free
    keys_any: tuple = ()

    async def fetch(self, ctx, domain) -> Iterable:
        raise NotImplementedError


class CrtSh(_Src):
    name = "crtsh"

    async def fetch(self, ctx, d):
        data = await api_get(ctx.api, "https://crt.sh/", params={"q": f"%.{d}", "output": "json"}, retries=4,
                             backoff=5, timeout=120)
        if data is None:  # fall back to the identity search which is often faster
            data = await api_get(ctx.api, "https://crt.sh/", params={"Identity": d, "output": "json"}, retries=2,
                                 backoff=5, timeout=120)
        return parse_crtsh(data)


class CertSpotter(_Src):
    name = "certspotter"

    async def fetch(self, ctx, d):
        out, after = [], None
        hdr = {"Authorization": f"Bearer {ctx.key('certspotter_key')}"} if ctx.key("certspotter_key") else None
        for _ in range(5):
            params = {"domain": d, "include_subdomains": "true", "expand": "dns_names"}
            if after:
                params["after"] = after
            data = await api_get(ctx.api, "https://api.certspotter.com/v1/issuances", params=params, headers=hdr)
            if not data:
                break
            out += parse_certspotter(data)
            after = data[-1].get("id")
            if len(data) < 100:
                break
        return out


class HackerTarget(_Src):
    name = "hackertarget"

    async def fetch(self, ctx, d):
        txt = await api_get(ctx.api, "https://api.hackertarget.com/hostsearch/", params={"q": d}, as_json=False)
        rows = parse_hackertarget(txt or "")
        for h, ip in rows:
            ctx.stats.setdefault("passive_ips", {}).setdefault(h.lower(), set()).add(ip) if ip else None
        return [h for h, _ in rows]


class OTX(_Src):
    name = "otx"

    async def fetch(self, ctx, d):
        hdr = {"X-OTX-API-KEY": ctx.key("otx_key")} if ctx.key("otx_key") else None
        data = await api_get(ctx.api, f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
                             headers=hdr, retries=2)
        return [h for h, _ in parse_otx(data)]


class URLScan(_Src):
    name = "urlscan"

    async def fetch(self, ctx, d):
        hdr = {"API-Key": ctx.key("urlscan_key")} if ctx.key("urlscan_key") else None
        data = await api_get(ctx.api, "https://urlscan.io/api/v1/search/", params={"q": f"domain:{d}", "size": 1000},
                             headers=hdr)
        return parse_urlscan(data)


class Anubis(_Src):
    name = "anubis"

    async def fetch(self, ctx, d):
        return parse_list(await api_get(ctx.api, f"https://jldc.me/anubis/subdomains/{d}"))


class RapidDNS(_Src):
    name = "rapiddns"

    async def fetch(self, ctx, d):
        txt = await api_get(ctx.api, f"https://rapiddns.io/subdomain/{d}", params={"full": "1"}, as_json=False)
        return list(ctx.scope.extract_hosts(txt or ""))


class SubdomainCenter(_Src):
    name = "subdomain_center"

    async def fetch(self, ctx, d):
        return parse_list(await api_get(ctx.api, "https://api.subdomain.center/", params={"domain": d}))


class Columbus(_Src):
    name = "columbus"

    async def fetch(self, ctx, d):
        data = await api_get(ctx.api, f"https://columbus.elmasy.com/api/lookup/{d}",
                             headers={"Accept": "application/json"})
        return labels_to_hosts(parse_list(data), d)


class VirusTotal(_Src):
    name = "virustotal"
    key = "virustotal_key"

    async def fetch(self, ctx, d):
        out, url = [], f"https://www.virustotal.com/api/v3/domains/{d}/subdomains?limit=40"
        for _ in range(10):
            data = await api_get(ctx.api, url, headers={"x-apikey": ctx.key(self.key)})
            if not data:
                break
            out += [x.get("id", "") for x in data.get("data", [])]
            url = (data.get("links") or {}).get("next")
            if not url:
                break
        return out


class SecurityTrails(_Src):
    name = "securitytrails"
    key = "securitytrails_key"

    async def fetch(self, ctx, d):
        data = await api_get(ctx.api, f"https://api.securitytrails.com/v1/domain/{d}/subdomains",
                             params={"children_only": "false"}, headers={"APIKEY": ctx.key(self.key)})
        return labels_to_hosts((data or {}).get("subdomains", []), d)


class Chaos(_Src):
    name = "chaos"
    key = "chaos_key"

    async def fetch(self, ctx, d):
        data = await api_get(ctx.api, f"https://dns.projectdiscovery.io/dns/{d}/subdomains",
                             headers={"Authorization": ctx.key(self.key)})
        return labels_to_hosts((data or {}).get("subdomains", []), d)


class ShodanDNS(_Src):
    name = "shodan"
    key = "shodan_key"

    async def fetch(self, ctx, d):
        data = await api_get(ctx.api, f"https://api.shodan.io/dns/domain/{d}", params={"key": ctx.key(self.key)})
        data = data or {}
        out = labels_to_hosts(data.get("subdomains", []), d)
        for rec in data.get("data", []):
            if rec.get("subdomain") is not None:
                out += labels_to_hosts([rec["subdomain"]], d) if rec["subdomain"] else []
            if rec.get("type") == "CNAME":
                out.append(rec.get("value", ""))
        return out


class FullHunt(_Src):
    name = "fullhunt"
    key = "fullhunt_key"

    async def fetch(self, ctx, d):
        data = await api_get(ctx.api, f"https://fullhunt.io/api/v1/domain/{d}/subdomains",
                             headers={"X-API-KEY": ctx.key(self.key)})
        return parse_list(data)


class GitHubCode(_Src):
    name = "github"
    key = "github_token"

    async def fetch(self, ctx, d):
        out = []
        hdr = {"Authorization": f"token {ctx.key(self.key)}", "Accept": "application/vnd.github.v3.text-match+json"}
        for page in range(1, 6):
            data = await api_get(ctx.api, "https://api.github.com/search/code",
                                 params={"q": f'"{d}"', "per_page": 100, "page": page}, headers=hdr, retries=1)
            if not data or not data.get("items"):
                break
            for it in data["items"]:
                for tm in it.get("text_matches", []):
                    out += list(ctx.scope.extract_hosts(tm.get("fragment", "")))
                ctx.emit("github_code", {"domain": d, "repo": (it.get("repository") or {}).get("full_name"),
                                         "path": it.get("path"), "url": it.get("html_url")})
            await asyncio.sleep(6)  # code search: 10 req/min
        return out


SOURCES: List[_Src] = [CrtSh(), CertSpotter(), HackerTarget(), OTX(), URLScan(), Anubis(), RapidDNS(),
                       SubdomainCenter(), Columbus(), VirusTotal(), SecurityTrails(), Chaos(), ShodanDNS(),
                       FullHunt(), GitHubCode()]


async def _run_tool(cmd: List[str], timeout: float) -> str:
    try:
        p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(p.communicate(), timeout)
        return out.decode("utf-8", "replace")
    except (OSError, asyncio.TimeoutError):
        try:
            p.kill()
        except Exception:  # noqa
            pass
        return ""


class PassiveSubdomains(Module):
    name = "passive"
    phase = 10
    mode = "passive"
    description = "Certificate transparency, passive DNS and search-engine subdomain sources"

    async def run(self, ctx):
        stats: Dict[str, dict] = ctx.stats.setdefault("sources", {})
        jobs = []
        for d in ctx.scope.roots:
            for src in SOURCES:
                if src.key and not ctx.key(src.key):
                    stats.setdefault(src.name, {"status": "skipped (no key)"})
                    continue
                jobs.append(self._one(ctx, src.name, src.fetch, d, stats))
            if ctx.cfg.tools:
                if shutil.which("subfinder"):
                    jobs.append(self._one(ctx, "subfinder", lambda c, dd: self._tool(
                        c, ["subfinder", "-d", dd, "-silent", "-all"]), d, stats))
                if shutil.which("amass"):
                    jobs.append(self._one(ctx, "amass", lambda c, dd: self._tool(
                        c, ["amass", "enum", "-passive", "-nocolor", "-d", dd], 900), d, stats))
        await asyncio.gather(*jobs)

    async def _tool(self, ctx, cmd, timeout=600):
        return list(ctx.scope.extract_hosts(await _run_tool(cmd, timeout)))

    async def _one(self, ctx, name: str, fn: Callable, domain: str, stats):
        st = stats.setdefault(name, {"status": "ok", "found": 0, "new": 0})
        try:
            res = await fn(ctx, domain)
        except Exception as e:  # noqa
            st["status"] = f"error: {type(e).__name__}: {e}"[:200]
            return
        found = 0
        for h in res or []:
            c = clean_host(h)
            if c and ctx.scope.in_scope(c):
                found += 1
                if ctx.add_host(c, name):
                    st["new"] = st.get("new", 0) + 1
        st["found"] = st.get("found", 0) + found
        if not res:
            st["status"] = "empty/failed"
        self.log.info("source %-16s %-25s %5d hosts", name, domain, found)
