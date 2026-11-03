"""WAF/CDN-security detection and (authorized) bypass assessment.

For each probed service we fingerprint the WAF vendor (wafw00f-style). For endpoints that return a
blocking status (401/403/406/429/501/503 or a generic block page) we run a measured set of documented,
read-only bypass probes and report which, if any, changed the outcome. This is standard authorized
bug-bounty recon: it tells a researcher whether an access control / WAF rule is trivially evadable.

All probes are GETs; nothing destructive is sent. Bypass attempts are capped and rate-aware.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..base import Module, gather_limited
from ..data.waf import GENERIC_BLOCK, WAF_SIGNATURES
from ..http import fetch
from ..util import simhash, hamming

GENERIC_RE = [re.compile(p) for p in GENERIC_BLOCK]
BLOCK_STATUS = {401, 403, 405, 406, 409, 419, 429, 494, 501, 503}

# header-based bypass vectors (origin-IP / internal-routing spoofing that WAFs & apps often trust)
HEADER_BYPASS = [
    {"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-For": "localhost"},
    {"X-Real-IP": "127.0.0.1"}, {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"}, {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"}, {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"}, {"X-Original-URL": "/"}, {"X-Rewrite-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"}, {"Forwarded": "for=127.0.0.1;host=localhost"},
    {"True-Client-IP": "127.0.0.1"}, {"Cluster-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"}, {"X-Forwarded-Server": "localhost"},
]
# path-mutation bypass vectors applied to a blocked path
PATH_MUTATORS = [
    lambda p: p + "/", lambda p: p + "/.", lambda p: "/." + p, lambda p: p + "//",
    lambda p: "//" + p.lstrip("/"), lambda p: p + "/..;/", lambda p: p + "%20",
    lambda p: p + "%09", lambda p: p + "?", lambda p: p + "#", lambda p: p + "%2e",
    lambda p: p.rstrip("/") + "/./", lambda p: p + ";/", lambda p: p + ".json",
    lambda p: p.upper() if p.lower() == p else p.lower(),
    lambda p: p.replace("/", "/%2e/", 1) if "/" in p[1:] else p,
]


def detect_waf(status: int, headers: Dict[str, str], cookies: List[str], body: str) -> List[dict]:
    body_s = body[:120000]
    cookie_s = "\n".join(cookies)
    server = headers.get("server", "")
    found = []
    for vendor, sig in WAF_SIGNATURES.items():
        hit = None
        for h, pat in sig.get("headers", {}).items():
            if h in headers and re.search(pat, headers[h], re.I):
                hit = f"header:{h}"
        for h in sig.get("header_present", []):
            if h in headers:
                hit = hit or f"header:{h}"
        for pat in sig.get("server", []):
            if re.search(pat, server, re.I):
                hit = hit or "server"
        for pat in sig.get("cookies", []):
            if re.search(pat, cookie_s, re.I | re.M):
                hit = hit or "cookie"
        for pat in sig.get("body", []):
            if re.search(pat, body_s):
                hit = hit or "body"
        if hit:
            conf = "high" if hit != "body" else "medium"
            if hit == "body" and status in sig.get("status", []):
                conf = "high"
            found.append({"vendor": vendor, "via": hit, "confidence": conf})
    return found


def looks_blocked(status: int, body: str) -> bool:
    if status in BLOCK_STATUS:
        return True
    return any(r.search(body[:60000]) for r in GENERIC_RE)


class WAFDetect(Module):
    name = "waf"
    phase = 58
    mode = "normal"
    final = True
    description = "Fingerprint WAF/CDN security and assess documented bypasses on blocked endpoints"

    async def run(self, ctx):
        services = [s for s in ctx.services.values() if s.get("status")]
        seen = set()
        uniq = []
        for s in sorted(services, key=lambda x: (x["scheme"] != "https",)):
            if s["host"] in seen:
                continue
            seen.add(s["host"])
            uniq.append(s)
        await gather_limited([self._service(ctx, s) for s in uniq], max(8, ctx.cfg.concurrency // 4))

    async def _service(self, ctx, svc):
        base = svc["url"]
        # root fingerprint (re-request to capture cookies/body fresh)
        r = await fetch(ctx.probe, base + "/", timeout=ctx.cfg.timeout, max_bytes=200000, allow_redirects=False)
        if not r:
            return
        wafs = detect_waf(r.status, r.headers, r.set_cookies(), r.text)
        # also probe a deliberately noisy path to provoke the WAF (safe, reflective marker)
        if not wafs:
            probe = await fetch(ctx.probe, base + "/?x=<rcnmstr>'\"", timeout=ctx.cfg.timeout, max_bytes=120000)
            if probe:
                wafs = detect_waf(probe.status, probe.headers, probe.set_cookies(), probe.text)
        if wafs:
            svc["waf"] = wafs
            for h in ctx.ips:
                pass
            vendor_list = ", ".join(sorted({w["vendor"] for w in wafs}))
            best = max(wafs, key=lambda w: w["confidence"] == "high")
            ctx.finding("waf", "info", best["confidence"], base, f"WAF/edge-security detected: {vendor_list}",
                        {"vendors": wafs}, self.name, ["waf"] + [w["vendor"].lower().split()[0] for w in wafs],
                        dedupe_key="waf")
            host = svc["host"]
            if ctx.hosts.get(host):
                ctx.hosts[host]["waf"] = vendor_list
        # bypass assessment on blocked endpoints (403 candidates recorded by probe, plus this root)
        await self._bypass_blocked(ctx, svc)

    async def _bypass_blocked(self, ctx, svc):
        base = svc["url"]
        # candidate blocked paths: any content/path finding on this host that returned 401/403, plus /admin etc.
        blocked_paths = set()
        root = await fetch(ctx.probe, base + "/", timeout=ctx.cfg.timeout, max_bytes=120000, allow_redirects=False)
        if root and looks_blocked(root.status, root.text):
            blocked_paths.add("/")
        for probe_path in ("/admin", "/admin/", "/.git/config", "/actuator", "/server-status", "/manager"):
            rr = await fetch(ctx.probe, base + probe_path, timeout=ctx.cfg.timeout, max_bytes=60000,
                             allow_redirects=False)
            if rr and rr.status in (401, 403):
                blocked_paths.add(probe_path)
        for path in list(blocked_paths)[:4]:
            await self._try_bypass(ctx, base, path)

    async def _try_bypass(self, ctx, base, path):
        baseline = await fetch(ctx.probe, base + path, timeout=ctx.cfg.timeout, max_bytes=60000,
                               allow_redirects=False)
        if not baseline or baseline.status not in BLOCK_STATUS:
            return
        bstatus = baseline.status
        bsim = simhash(baseline.text)
        wins = []

        async def check(label, url=None, headers=None, method="GET"):
            r = await fetch(ctx.probe, url or (base + path), headers=headers, method=method,
                            timeout=ctx.cfg.timeout, max_bytes=120000, allow_redirects=False)
            if not r:
                return
            # a "win" = previously-blocked now returns 2xx (or a materially different allowed body)
            if r.status < 400 and r.status != bstatus and hamming(bsim, simhash(r.text)) > 6:
                wins.append({"technique": label, "new_status": r.status, "from_status": bstatus,
                             "detail": headers or method or url})

        jobs = [check(f"header:{list(h)[0]}", headers=h) for h in HEADER_BYPASS]
        jobs += [check(f"method:{m}", method=m) for m in ("POST", "HEAD", "OPTIONS", "TRACE", "PUT", "FOOBAR")]
        jobs += [check(f"path:{mut(path)}", url=base + mut(path)) for mut in PATH_MUTATORS]
        await gather_limited(jobs, 12)
        if wins:
            ctx.finding("waf_bypass", "high", "high", base + path,
                        f"Access control / WAF bypass on {path} ({len(wins)} technique(s) returned 2xx)",
                        {"blocked_status": bstatus, "bypasses": wins[:20]}, self.name, ["waf", "bypass", "403"],
                        dedupe_key=path,
                        next_steps=["Reproduce the winning request manually and confirm sensitive access"])
