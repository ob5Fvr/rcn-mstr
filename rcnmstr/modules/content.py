"""Content discovery with soft-404 calibration: sensitive paths verified by content signature, not status alone."""
from __future__ import annotations

import asyncio
import re
from typing import Callable, Dict, List, Optional, Tuple

from ..base import Module, gather_limited
from ..http import fetch
from ..util import hamming, simhash

# path -> (severity, signature callable(status, headers, body) -> bool, tags, description)
import base64 as _b64


def _has(*subs):
    return lambda s, h, b: any(x in b for x in subs)


def _re(*pats):
    comp = [re.compile(p, re.I | re.S) for p in pats]
    return lambda s, h, b: any(c.search(b) for c in comp)


def _status(*codes):
    return lambda s, h, b: s in codes


def _git_head(s, h, b):
    return s == 200 and b.lstrip().startswith("ref: refs/")


def _env(s, h, b):
    return s == 200 and bool(re.search(r"^[A-Z0-9_]{2,}=[^\n]*", b, re.M)) and "<html" not in b[:200].lower()


def _dsstore(s, h, b):
    return s == 200 and b[:4] == "\x00\x00\x00\x01" and "Bud1" in b[:64]


def _prom(s, h, b):
    return s == 200 and ("# HELP " in b or "# TYPE " in b)


def _json_key(*keys):
    return lambda s, h, b: s == 200 and "json" in h.get("content-type", "") and any(k in b for k in keys)


PATHS: Dict[str, Tuple[str, Callable, list, str]] = {
    # VCS / source leaks
    ".git/HEAD": ("high", _git_head, ["vcs", "source-leak"], "Exposed .git repository"),
    ".git/config": ("high", _re(r"\[core\]", r"repositoryformatversion"), ["vcs"], "Exposed .git/config"),
    ".gitignore": ("info", lambda s, h, b: s == 200 and "\n" in b and "<html" not in b[:100].lower(), ["vcs"], ".gitignore readable"),
    ".svn/entries": ("high", _re(r"^\d+\s*$|dir\n|svn:"), ["vcs"], "Exposed .svn"),
    ".svn/wc.db": ("high", lambda s, h, b: s == 200 and b[:15] == "SQLite format 3", ["vcs"], "Exposed .svn/wc.db"),
    ".hg/requires": ("medium", _status(200), ["vcs"], "Exposed Mercurial repo"),
    ".bzr/README": ("medium", _status(200), ["vcs"], "Exposed Bazaar repo"),
    ".DS_Store": ("low", _dsstore, ["info-leak"], "Exposed .DS_Store (file listing)"),
    "bitbucket-pipelines.yml": ("low", _re(r"pipelines:", r"image:"), ["ci"], "CI config exposed"),
    ".gitlab-ci.yml": ("low", _re(r"stages:", r"script:"), ["ci"], "GitLab CI config exposed"),
    # secrets / config
    ".env": ("critical", _env, ["secret", "config"], "Exposed .env file"),
    ".env.local": ("critical", _env, ["secret"], "Exposed .env.local"),
    ".env.production": ("critical", _env, ["secret"], "Exposed .env.production"),
    "config.json": ("medium", _json_key('"', ":"), ["config"], "config.json readable"),
    "appsettings.json": ("high", _json_key("ConnectionStrings", "AllowedHosts", "Logging"), ["config", "dotnet"], "ASP.NET appsettings.json exposed"),
    "wp-config.php.bak": ("critical", _re(r"DB_PASSWORD", r"DB_NAME"), ["secret", "wordpress"], "WordPress config backup"),
    "docker-compose.yml": ("medium", _re(r"services:", r"image:"), ["config", "docker"], "docker-compose.yml exposed"),
    "Dockerfile": ("low", _re(r"^FROM ", r"RUN "), ["config", "docker"], "Dockerfile exposed"),
    "phpinfo.php": ("medium", _re(r"phpinfo\(\)", r"PHP Version"), ["info-leak", "php"], "phpinfo() exposed"),
    "info.php": ("medium", _re(r"phpinfo\(\)", r"PHP Version"), ["info-leak", "php"], "phpinfo() exposed"),
    "server-status": ("medium", _re(r"Apache Server Status", r"Server uptime"), ["info-leak", "apache"], "Apache mod_status exposed"),
    "server-info": ("medium", _re(r"Apache Server Information"), ["info-leak", "apache"], "Apache mod_info exposed"),
    # spring / actuator / jmx
    "actuator": ("medium", _json_key("_links", "health", "env"), ["actuator", "spring"], "Spring Boot actuator index"),
    "actuator/env": ("high", _json_key("propertySources", "systemEnvironment"), ["actuator", "spring"], "Spring actuator /env (may leak secrets)"),
    "actuator/health": ("info", _json_key('"status"'), ["actuator"], "Spring actuator /health"),
    "actuator/heapdump": ("high", lambda s, h, b: s == 200 and (b[:4] in ("JAVA", "\x00\x00\x00\x00") or "octet-stream" in h.get("content-type", "")), ["actuator", "spring"], "Spring actuator heapdump downloadable"),
    "actuator/mappings": ("low", _json_key("mappings", "dispatcherServlets"), ["actuator"], "Spring actuator /mappings"),
    "env": ("high", _json_key("propertySources"), ["actuator"], "Actuator /env (legacy path)"),
    "jolokia": ("high", _json_key("agent", "value", "request"), ["jmx", "jolokia"], "Jolokia JMX endpoint"),
    "jolokia/list": ("high", _json_key("value", "domains"), ["jmx"], "Jolokia list (JMX enumeration)"),
    "metrics": ("low", _prom, ["metrics"], "Prometheus metrics exposed"),
    "actuator/prometheus": ("low", _prom, ["metrics"], "Actuator Prometheus metrics"),
    "debug/pprof/": ("medium", _re(r"/debug/pprof/", r"goroutine profiles"), ["debug", "golang"], "Go pprof debug endpoint"),
    "debug/vars": ("medium", _json_key("cmdline", "memstats"), ["debug", "golang"], "Go expvar endpoint"),
    "trace.axd": ("medium", _re(r"Application Trace", r"trace.axd"), ["debug", "dotnet"], "ASP.NET trace.axd"),
    "elmah.axd": ("medium", _re(r"Error Log for", r"ELMAH"), ["debug", "dotnet"], "ELMAH error log"),
    "_profiler": ("medium", _re(r"Symfony Profiler", r"sf-toolbar"), ["debug", "symfony"], "Symfony profiler"),
    "telescope/requests": ("medium", _re(r"Telescope", r"Laravel"), ["debug", "laravel"], "Laravel Telescope"),
    "console": ("high", _re(r"Werkzeug", r"Interactive Console", r"__debugger__"), ["debug"], "Werkzeug debug console"),
    # api docs / schema
    "swagger.json": ("low", _json_key('"swagger"', '"openapi"', '"paths"'), ["api-docs"], "Swagger spec"),
    "openapi.json": ("low", _json_key('"openapi"', '"paths"'), ["api-docs"], "OpenAPI spec"),
    "api-docs": ("low", _json_key('"swagger"', '"openapi"'), ["api-docs"], "API docs (swagger)"),
    "v2/api-docs": ("low", _json_key('"swagger"', '"paths"'), ["api-docs"], "Springfox API docs"),
    "v3/api-docs": ("low", _json_key('"openapi"', '"paths"'), ["api-docs"], "OpenAPI v3 docs"),
    "swagger-ui.html": ("low", _re(r"swagger-ui", r"Swagger UI"), ["api-docs"], "Swagger UI"),
    "swagger/index.html": ("low", _re(r"swagger-ui", r"Swagger UI"), ["api-docs"], "Swagger UI"),
    # config/meta
    "crossdomain.xml": ("low", lambda s, h, b: s == 200 and 'domain="*"' in b.replace("'", '"'), ["cors"], "crossdomain.xml with wildcard"),
    "clientaccesspolicy.xml": ("low", _re(r"<access-policy", r'uri="\*"'), ["cors"], "Silverlight access policy"),
    "robots.txt": ("info", lambda s, h, b: s == 200 and re.search(r"(?i)(dis)?allow:", b), ["recon"], "robots.txt"),
    "sitemap.xml": ("info", _re(r"<urlset", r"<sitemapindex", r"<loc>"), ["recon"], "sitemap.xml"),
    ".well-known/security.txt": ("info", _re(r"Contact:", r"Policy:"), ["recon"], "security.txt"),
    ".well-known/openid-configuration": ("info", _json_key("issuer", "authorization_endpoint"), ["oidc"], "OIDC configuration"),
    ".well-known/assetlinks.json": ("info", _json_key("relation", "target"), ["mobile"], "Android asset links"),
    ".well-known/apple-app-site-association": ("info", _json_key("applinks", "webcredentials"), ["mobile"], "Apple app site association"),
    # backups
    "backup.zip": ("high", lambda s, h, b: s == 200 and b[:2] == "PK", ["backup"], "backup.zip downloadable"),
    "backup.sql": ("high", _re(r"CREATE TABLE", r"INSERT INTO", r"-- MySQL dump"), ["backup", "database"], "SQL dump downloadable"),
    "dump.sql": ("high", _re(r"CREATE TABLE", r"INSERT INTO"), ["backup", "database"], "SQL dump downloadable"),
    "db.sql": ("high", _re(r"CREATE TABLE", r"INSERT INTO"), ["backup"], "SQL dump downloadable"),
    "www.zip": ("high", lambda s, h, b: s == 200 and b[:2] == "PK", ["backup"], "Site archive downloadable"),
    "web.config": ("medium", _re(r"<configuration", r"<system.web"), ["config", "dotnet"], "web.config exposed"),
    # graphql handled separately (POST)
}


class ContentDiscovery(Module):
    name = "content"
    phase = 60
    mode = "normal"
    final = True
    description = "Probe ~90 sensitive paths, verified by content signature with soft-404 calibration"

    async def run(self, ctx):
        services = [s for s in ctx.services.values() if s["status"] < 500 and s["status"] != 429]
        # one representative service per (host) to avoid hammering http+https duplicates
        seen = set()
        uniq = []
        for s in sorted(services, key=lambda x: (x["scheme"] != "https", x["port"])):
            if s["host"] in seen:
                continue
            seen.add(s["host"])
            uniq.append(s)
        self.log.info("content discovery on %d services", len(uniq))
        await gather_limited([self._service(ctx, s) for s in uniq], max(10, ctx.cfg.concurrency // 4))

    async def _calibrate(self, ctx, base) -> Optional[dict]:
        """Request random paths to learn the soft-404 signature."""
        import os
        sigs = []
        for _ in range(2):
            rnd = os.urandom(8).hex()
            r = await fetch(ctx.probe, f"{base}/{rnd}-rcn404/", timeout=ctx.cfg.timeout, max_bytes=100000)
            if r:
                sigs.append({"status": r.status, "simhash": simhash(r.text), "len": len(r.body)})
        if not sigs:
            return None
        return {"statuses": {s["status"] for s in sigs}, "simhashes": [s["simhash"] for s in sigs],
                "soft404": any(s["status"] == 200 for s in sigs)}

    def _is_soft404(self, cal, status, body) -> bool:
        if cal is None:
            return False
        if status in cal["statuses"] and status == 200:
            sh = simhash(body)
            return any(hamming(sh, c) <= 6 for c in cal["simhashes"])
        return False

    async def _service(self, ctx, svc):
        base = svc["url"]
        cal = await self._calibrate(ctx, base)
        paths = list(PATHS.items())
        for p in list(ctx.paths)[:40]:  # paths learned from robots/js/archives
            if p not in PATHS and p.count("/") <= 3:
                paths.append((p.lstrip("/"), ("info", lambda s, h, b: s == 200 and len(b) > 0, ["learned"], f"Discovered path {p}")))
        results = await gather_limited([self._path(ctx, svc, base, path, meta, cal) for path, meta in paths],
                                       max(8, ctx.cfg.concurrency // 4))
        hits = [r for r in results if r]
        if hits:
            svc.setdefault("content", []).extend(hits)
        await self._graphql(ctx, base)

    async def _path(self, ctx, svc, base, path, meta, cal) -> Optional[dict]:
        severity, sig, tags, desc = meta
        url = f"{base}/{path}"
        r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=1_000_000, allow_redirects=False)
        if not r or r.status in (429,):
            return None
        body = r.text
        if self._is_soft404(cal, r.status, body):
            return None
        try:
            if not sig(r.status, r.headers, body):
                return None
        except Exception:  # noqa
            return None
        conf = "high" if severity in ("high", "critical") else "medium"
        finding = {"path": "/" + path, "status": r.status, "length": len(r.body),
                   "content_type": r.header("content-type")}
        ctx.finding("content_exposure", severity, conf, url, desc, finding, self.name, ["content"] + tags,
                    dedupe_key=path)
        if path == "robots.txt" or path == "sitemap.xml":
            for m in re.finditer(r"(?:Allow|Disallow):\s*(\S+)", body, re.I):
                ctx.paths.add(m.group(1))
            ctx.add_hosts(ctx.scope.extract_hosts(body), "robots")
        return {**finding, "severity": severity}

    async def _graphql(self, ctx, base):
        query = {"query": "{__schema{queryType{name} types{name kind}}}"}
        for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
            r = await fetch(ctx.probe, base + path, method="POST", json_body=query, timeout=ctx.cfg.timeout,
                            max_bytes=200000)
            if r and r.status == 200 and "__schema" in r.text and '"types"' in r.text:
                ctx.finding("content_exposure", "medium", "high", base + path,
                            "GraphQL introspection enabled", {"path": path}, self.name,
                            ["graphql", "introspection"], dedupe_key=path,
                            next_steps=["Dump full schema; look for sensitive queries/mutations"])
                return
