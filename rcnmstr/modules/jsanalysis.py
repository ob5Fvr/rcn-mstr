"""Crawl HTML, pull JS + source maps, extract endpoints / hosts / cloud refs / internal IPs, scan for secrets."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..base import Module, gather_limited
from ..data.secrets import PLACEHOLDERS, RULES
from ..http import fetch
from ..scope import clean_host
from ..util import is_private_ip, redact, shannon_entropy

SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
LINK_RE = re.compile(r'<(?:a|link)[^>]+href=["\']([^"\']+)["\']', re.I)
# LinkFinder-style endpoint regex
ENDPOINT_RE = re.compile(r"""(?:"|')(
  (?:/|\.\./|\./)[^"'><,;|*()%%$^\s]{1,}
  |[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:php|asp|aspx|jsp|json|js|action|html|do|xml|api)(?:[?][^"'<>\s]*)?
  |[a-zA-Z0-9_\-]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[?][^"'<>\s]*)?
  |/(?:api|v[0-9]|graphql|rest|internal|admin|auth|oauth|rpc)/[^"'><,;|*()%%$^\s]{1,}
)(?:"|')""", re.X)
CLOUD_RE = re.compile(
    r"(?:https?://)?([a-z0-9][a-z0-9.\-_]{1,62})\.s3[.\-](?:[a-z0-9-]+\.)?amazonaws\.com"
    r"|s3[.\-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.\-_]{1,62})"
    r"|(?:https?://)?([a-z0-9][a-z0-9.\-_]{1,62})\.storage\.googleapis\.com"
    r"|storage\.googleapis\.com/([a-z0-9][a-z0-9.\-_]{1,62})"
    r"|(?:https?://)?([a-z0-9][a-z0-9-]{1,62})\.blob\.core\.windows\.net"
    r"|(?:https?://)?([a-z0-9][a-z0-9.\-_]{1,62})\.(?:[a-z0-9-]+\.)?digitaloceanspaces\.com", re.I)
INTERNAL_IP_RE = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|127\.\d{1,3})"
                            r"\.\d{1,3}\.\d{1,3}\b")
SOURCEMAP_RE = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s*]+)")


def extract_secrets(text: str, source: str) -> List[dict]:
    out = []
    seen = set()
    for name, rx, needs_ent, min_ent in RULES:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if not val or val in seen:
                continue
            if PLACEHOLDERS.match(val):
                continue
            if needs_ent and shannon_entropy(val) < min_ent:
                continue
            seen.add(val)
            ctx_start = max(0, m.start() - 40)
            out.append({"rule": name, "match": redact(val), "match_len": len(val),
                        "entropy": round(shannon_entropy(val), 2), "source": source,
                        "context": re.sub(r"\s+", " ", text[ctx_start:m.end() + 20])[:120]})
    return out


class JSAnalysis(Module):
    name = "js"
    phase = 65
    mode = "normal"
    final = True
    description = "Crawl pages, analyse JS/source maps for endpoints, hosts, cloud buckets, internal IPs, secrets"

    async def run(self, ctx):
        services = [s for s in ctx.services.values() if s["status"] < 400 and "html" in (s.get("content_type") or "html")]
        seen_host = set()
        roots = []
        for s in sorted(services, key=lambda x: (x["scheme"] != "https",)):
            if s["host"] in seen_host:
                continue
            seen_host.add(s["host"])
            roots.append(s["url"])
        self.log.info("js/crawl starting on %d origins", len(roots))
        self.js_seen: Set[str] = set()
        self.js_count = 0
        await gather_limited([self._crawl(ctx, url) for url in roots], max(6, ctx.cfg.concurrency // 6))

    async def _crawl(self, ctx, base_url):
        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(base_url, 0)]
        js_urls: Set[str] = set()
        host = urlparse(base_url).netloc
        while queue and len(visited) < ctx.cfg.max_crawl_pages:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=2_000_000)
            if not r:
                continue
            body = r.text
            self._scan_text(ctx, body, url)
            for m in SCRIPT_RE.finditer(body):
                js_urls.add(urljoin(url, m.group(1)))
            if depth < ctx.cfg.crawl_depth:
                for m in LINK_RE.finditer(body):
                    nxt = urljoin(url, m.group(1))
                    p = urlparse(nxt)
                    if p.netloc == host and p.scheme in ("http", "https") and nxt not in visited:
                        if not re.search(r"\.(png|jpg|jpeg|gif|svg|css|woff2?|ttf|ico|pdf|zip|mp4)(\?|$)", nxt, re.I):
                            queue.append((nxt, depth + 1))
        await gather_limited([self._js(ctx, u) for u in js_urls if u not in self.js_seen],
                             max(6, ctx.cfg.concurrency // 4))

    async def _js(self, ctx, url):
        if url in self.js_seen or self.js_count >= ctx.cfg.max_js:
            return
        self.js_seen.add(url)
        self.js_count += 1
        r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=5_000_000)
        if not r or r.status != 200:
            return
        body = r.text
        self._scan_text(ctx, body, url, is_js=True)
        m = SOURCEMAP_RE.search(body[-4000:]) or SOURCEMAP_RE.search(body)
        if m and not m.group(1).startswith("data:"):
            await self._sourcemap(ctx, urljoin(url, m.group(1)), url)

    async def _sourcemap(self, ctx, map_url, js_url):
        r = await fetch(ctx.probe, map_url, timeout=ctx.cfg.timeout, max_bytes=20_000_000)
        if not r or r.status != 200:
            return
        try:
            data = json.loads(r.text)
        except ValueError:
            return
        sources = data.get("sources", [])
        ctx.finding("source_map", "low", "high", map_url, f"JavaScript source map exposes {len(sources)} source files",
                    {"js": js_url, "files": sources[:60], "total": len(sources)}, self.name,
                    ["source-leak", "sourcemap"], dedupe_key=map_url,
                    next_steps=["Reconstruct original source from sourcesContent for logic/secret review"])
        for content in (data.get("sourcesContent") or [])[:200]:
            if content:
                self._scan_text(ctx, content, map_url + " (source)", is_js=True)

    def _scan_text(self, ctx, text, source, is_js=False):
        # hosts feedback
        new_hosts = ctx.scope.extract_hosts(text)
        ctx.add_hosts(new_hosts, "js" if is_js else "html")
        # endpoints
        for m in ENDPOINT_RE.finditer(text):
            ep = m.group(1).strip()
            if 1 < len(ep) < 250 and not ep.startswith(("//", "http")):
                path = ep.split("?")[0]
                if re.match(r"^[/a-zA-Z0-9]", path):
                    ctx.paths.add(path if path.startswith("/") else "/" + path)
                    q = ep.split("?", 1)
                    if len(q) == 2:
                        for pair in re.split(r"[&;]", q[1]):
                            k = pair.split("=")[0]
                            if re.match(r"^[a-zA-Z0-9_\-\[\]]{1,40}$", k):
                                ctx.params.add(k)
        # cloud bucket refs
        for m in CLOUD_RE.finditer(text):
            bucket = next((g for g in m.groups() if g), None)
            if bucket and 3 <= len(bucket) <= 63:
                ctx.cloud_refs.add(m.group(0).lower())
        # internal IPs
        internal = {ip for ip in INTERNAL_IP_RE.findall(text) if is_private_ip(ip)}
        if internal and is_js:
            ctx.finding("info_leak", "low", "medium", source, f"Internal IP address(es) in JS: {len(internal)}",
                        {"ips": sorted(internal)[:30]}, self.name, ["info-leak", "internal-ip"], dedupe_key=source)
        # secrets
        secrets = extract_secrets(text, source)
        for s in secrets:
            sev = "high" if s["rule"] in ("aws_secret_key", "private_key", "stripe_secret", "gcp_service_account",
                                          "github_pat", "github_fine_grained", "azure_storage_key",
                                          "google_api_key", "slack_token", "mongodb_uri", "postgres_uri",
                                          "ssh_private_key_openssh", "digitalocean_pat") else "medium"
            ctx.finding("secret", sev, "medium" if s["rule"].startswith("generic") else "high", source,
                        f"Possible {s['rule']} in {'JS' if is_js else 'HTML'}", s, self.name, ["secret", s["rule"]],
                        dedupe_key=f"{s['rule']}:{s['match']}",
                        next_steps=["Validate the credential out-of-band; do not use it"])
