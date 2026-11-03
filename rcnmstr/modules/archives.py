"""Archived URLs from Wayback / Common Crawl / OTX / urlscan; uro-style dedupe; gf-style classification."""
from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Set
from urllib.parse import parse_qs, urlparse

from ..base import Module, gather_limited
from ..http import api_get, fetch

PARAM_PATTERNS = {
    "xss": ["q", "s", "search", "query", "keyword", "id", "name", "message", "msg", "comment", "text",
            "redirect", "url", "return", "callback", "content", "html", "data", "lang", "page"],
    "ssrf": ["url", "uri", "path", "dest", "redirect", "redirect_uri", "return", "returnurl", "next", "data",
             "reference", "site", "html", "val", "validate", "domain", "callback", "feed", "host", "port",
             "to", "out", "view", "dir", "show", "navigation", "open", "image", "img", "source", "load",
             "file", "window", "proxy", "fetch", "resource"],
    "redirect": ["redirect", "redirect_uri", "redirect_url", "return", "returnurl", "return_url", "next",
                 "url", "target", "rurl", "dest", "destination", "redir", "redirecturl", "continue", "goto",
                 "out", "view", "login_url", "image_url", "go", "callback", "forward"],
    "sqli": ["id", "page", "dir", "search", "category", "file", "class", "news", "item", "menu", "lang",
             "name", "ref", "title", "view", "topic", "thread", "type", "date", "form", "join", "main",
             "nav", "region", "order", "sort", "where", "query", "user", "uid", "number"],
    "lfi": ["file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "php_path",
            "doc", "page", "name", "cat", "dir", "action", "board", "date", "detail", "download", "prefix",
            "include", "inc", "locate", "show", "site", "type", "view", "content", "layout", "mod", "conf"],
    "rce": ["cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func",
            "arg", "option", "load", "process", "step", "read", "function", "req", "feature", "exe",
            "module", "payload", "run", "print", "daemon", "upload", "dir", "download", "log", "ip"],
    "idor": ["id", "user_id", "uid", "account", "account_id", "number", "order", "order_id", "no", "doc",
             "key", "email", "group", "profile", "edit", "report", "invoice", "customer", "cart"],
    "ssti": ["preview", "activity", "id", "page", "name", "message", "template", "query", "redirect"],
}
INTERESTING_EXT = {"bak", "sql", "zip", "tar", "gz", "tgz", "7z", "rar", "env", "config", "conf", "cfg",
                   "json", "xml", "yml", "yaml", "log", "old", "backup", "swp", "git", "pem", "key", "p12",
                   "pfx", "jks", "db", "sqlite", "dump", "csv", "xls", "xlsx", "doc", "docx", "pdf", "ini",
                   "properties", "war", "jar", "class", "inc", "orig", "save", "tmp", "cache"}
EXTENSION_RE = re.compile(r"\.([a-z0-9]{1,6})(?:$|\?)", re.I)
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
HASH_RE = re.compile(r"\b[0-9a-f]{16,64}\b", re.I)
NUM_RE = re.compile(r"\d+")


def uro_key(url: str) -> str:
    """Collapse numeric/uuid/hash path segments and parameter *values* so near-dupe URLs collapse."""
    p = urlparse(url)
    segs = []
    for seg in p.path.split("/"):
        s = UUID_RE.sub("{uuid}", seg)
        s = HASH_RE.sub("{hash}", s)
        s = NUM_RE.sub("{n}", s)
        segs.append(s)
    path = "/".join(segs)
    params = sorted(parse_qs(p.query).keys())
    return f"{p.netloc}{path}?{'&'.join(params)}" if params else f"{p.netloc}{path}"


def classify(url: str) -> Dict[str, list]:
    p = urlparse(url)
    params = list(parse_qs(p.query).keys())
    tags = {}
    for cat, names in PARAM_PATTERNS.items():
        hit = [param for param in params if param.lower() in names]
        if hit:
            tags[cat] = hit
    m = EXTENSION_RE.search(p.path)
    if m and m.group(1).lower() in INTERESTING_EXT:
        tags["interesting_ext"] = [m.group(1).lower()]
    return tags


class Archives(Module):
    name = "archives"
    phase = 70
    mode = "normal"
    final = True
    description = "Wayback/CommonCrawl/OTX/urlscan URL harvest, uro-dedupe, gf-classify, optional live recheck"

    async def run(self, ctx):
        all_urls: Set[str] = set()
        for d in ctx.scope.roots:
            for coro in (self._wayback(ctx, d), self._commoncrawl(ctx, d), self._otx(ctx, d), self._urlscan(ctx, d)):
                try:
                    all_urls |= await coro
                except Exception as e:  # noqa
                    self.log.debug("archive source failed: %s", e)
        self.log.info("archives: %d raw urls", len(all_urls))
        # feed in-scope hosts back
        host_set = set()
        for u in all_urls:
            h = urlparse(u).netloc.split(":")[0]
            if h and h not in host_set:
                host_set.add(h)
        ctx.add_hosts(host_set, "archive")
        # uro dedupe
        collapsed: Dict[str, str] = {}
        classified = {}
        for u in all_urls:
            k = uro_key(u)
            if k not in collapsed:
                collapsed[k] = u
                tags = classify(u)
                if tags:
                    classified[u] = tags
        ctx.stats["archive_urls"] = {"raw": len(all_urls), "deduped": len(collapsed)}
        ctx.write_lines("urls_all.txt", sorted(collapsed.values()))
        for u, tags in classified.items():
            ctx.emit("archive_url", {"url": u, "tags": tags})
            for param in tags.get("interesting_ext", []):
                pass
        # params + paths feedback
        for u in collapsed.values():
            p = urlparse(u)
            for param in parse_qs(p.query):
                if re.match(r"^[a-zA-Z0-9_\-\[\]]{1,40}$", param):
                    ctx.params.add(param)
            if p.path and p.path != "/":
                ctx.paths.add(p.path)
        if ctx.params:
            ctx.write_lines("params.txt", sorted(ctx.params))
        # summarise interesting classes as findings
        for cat in PARAM_PATTERNS:
            hits = [u for u, t in classified.items() if cat in t]
            if hits:
                ctx.finding("archive_params", "info", "low", ctx.scope.roots[0],
                            f"{len(hits)} archived URL(s) with {cat}-prone parameters",
                            {"category": cat, "sample": hits[:20]}, self.name, ["archive", cat],
                            dedupe_key=cat)
        ext_hits = [u for u, t in classified.items() if "interesting_ext" in t]
        if ext_hits and ctx.cfg.recheck_archive:
            await self._recheck(ctx, ext_hits)

    async def _recheck(self, ctx, urls):
        live = []
        results = await gather_limited(
            [fetch(ctx.probe, u, timeout=ctx.cfg.timeout, max_bytes=4096, method="HEAD") for u in urls[:500]],
            max(10, ctx.cfg.concurrency // 2))
        for u, r in zip(urls[:500], results):
            if r and r.status == 200:
                live.append({"url": u, "status": r.status, "length": r.header("content-length")})
        if live:
            ctx.finding("archive_live_file", "medium", "medium", ctx.scope.roots[0],
                        f"{len(live)} archived sensitive file(s) still reachable (HTTP 200)",
                        {"files": live[:40]}, self.name, ["archive", "exposure"],
                        next_steps=["Download and inspect each file for secrets/backups"])

    async def _wayback(self, ctx, domain) -> Set[str]:
        data = await api_get(ctx.api, "https://web.archive.org/cdx/search/cdx",
                             params={"url": f"*.{domain}/*", "output": "json", "fl": "original",
                                     "collapse": "urlkey", "limit": ctx.cfg.archive_limit}, retries=2, timeout=120)
        out = set()
        if isinstance(data, list):
            for row in data[1:]:
                if row:
                    out.add(row[0])
        return out

    async def _commoncrawl(self, ctx, domain) -> Set[str]:
        idx = await api_get(ctx.api, "https://index.commoncrawl.org/collinfo.json", retries=1)
        if not isinstance(idx, list) or not idx:
            return set()
        api = idx[0].get("cdx-api")
        txt = await api_get(ctx.api, api, params={"url": f"*.{domain}/*", "output": "json",
                            "fl": "url", "limit": min(ctx.cfg.archive_limit, 20000)}, as_json=False, retries=2,
                            timeout=120)
        out = set()
        for line in (txt or "").splitlines():
            try:
                import json
                out.add(json.loads(line)["url"])
            except (ValueError, KeyError):
                pass
        return out

    async def _otx(self, ctx, domain) -> Set[str]:
        out, page = set(), 1
        while page <= 10:
            data = await api_get(ctx.api, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
                                 params={"limit": 500, "page": page}, retries=1)
            if not isinstance(data, dict) or not data.get("url_list"):
                break
            for u in data["url_list"]:
                if u.get("url"):
                    out.add(u["url"])
            if not data.get("has_next"):
                break
            page += 1
        return out

    async def _urlscan(self, ctx, domain) -> Set[str]:
        hdr = {"API-Key": ctx.key("urlscan_key")} if ctx.key("urlscan_key") else None
        data = await api_get(ctx.api, "https://urlscan.io/api/v1/search/",
                             params={"q": f"domain:{domain}", "size": 1000}, headers=hdr, retries=1)
        out = set()
        for r in (data or {}).get("results", []):
            u = (r.get("page") or {}).get("url") or (r.get("task") or {}).get("url")
            if u:
                out.add(u)
        return out
