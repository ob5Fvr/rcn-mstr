"""HTTP plumbing: probe session (own DNS, no TLS verification) and API session (system CA, honours proxies)."""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
from dataclasses import dataclass, field
import time
from collections import defaultdict
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

from .util import is_ip


class HostRateLimiter:
    """Per-host politeness: cap requests/sec and concurrent in-flight per host.

    rate <= 0 disables rate limiting (only the per-host concurrency cap applies).
    """

    def __init__(self, rate: float = 0.0, per_host: int = 8):
        self.rate = rate
        self.min_interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self.per_host = max(1, per_host)
        self._last: dict = defaultdict(float)
        self._sem: dict = {}
        self._lock = asyncio.Lock()

    def _sem_for(self, host: str) -> asyncio.Semaphore:
        s = self._sem.get(host)
        if s is None:
            s = self._sem[host] = asyncio.Semaphore(self.per_host)
        return s

    async def acquire(self, host: str):
        await self._sem_for(host).acquire()
        if self.min_interval:
            async with self._lock:
                now = time.monotonic()
                wait = self._last[host] + self.min_interval - now
                self._last[host] = max(now, self._last[host] + self.min_interval)
            if wait > 0:
                await asyncio.sleep(wait)

    def release(self, host: str):
        s = self._sem.get(host)
        if s is not None:
            s.release()

log = logging.getLogger("rcnmstr.http")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


class CacheResolver(AbstractResolver):
    """aiohttp resolver backed by rcnmstr's own DNS stack (never the system resolver)."""

    def __init__(self, resolver):
        self.r = resolver

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        if is_ip(host):
            fam = socket.AF_INET6 if ":" in host else socket.AF_INET
            return [{"hostname": host, "host": host, "port": port, "family": fam, "proto": 0,
                     "flags": socket.AI_NUMERICHOST}]
        info = await self.r.resolve_host(host)
        out = []
        for ip in info["a"]:
            out.append({"hostname": host, "host": ip, "port": port, "family": socket.AF_INET, "proto": 0,
                        "flags": socket.AI_NUMERICHOST})
        if family in (socket.AF_INET6, socket.AF_UNSPEC, 0):
            for ip in info["aaaa"]:
                out.append({"hostname": host, "host": ip, "port": port, "family": socket.AF_INET6, "proto": 0,
                            "flags": socket.AI_NUMERICHOST})
        if not out:
            raise OSError(f"rcnmstr dns: cannot resolve {host} ({info['rcode']})")
        return out

    async def close(self):
        pass


@dataclass
class Resp:
    url: str
    status: int
    headers: Dict[str, str]
    raw_headers: List[tuple]
    body: bytes
    history: List[dict] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return self.body.decode("latin-1")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:  # noqa
            return None

    def set_cookies(self) -> List[str]:
        return [v for k, v in self.raw_headers if k.lower() == "set-cookie"]


def make_probe_session(resolver, concurrency: int = 100, timeout: float = 10.0, proxy: Optional[str] = None,
                       user_agent: str = UA, headers: Optional[dict] = None, rate: float = 0.0,
                       per_host: int = 10) -> aiohttp.ClientSession:
    conn = aiohttp.TCPConnector(ssl=False, resolver=CacheResolver(resolver), limit=concurrency,
                                limit_per_host=per_host, use_dns_cache=False, enable_cleanup_closed=True,
                                force_close=False)
    h = {"User-Agent": user_agent, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.8"}
    h.update(headers or {})
    s = aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=timeout, sock_connect=min(6, timeout)),
                              headers=h, cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
                              auto_decompress=True)
    s._rcn_proxy = proxy  # type: ignore[attr-defined]
    s._rcn_limiter = HostRateLimiter(rate, per_host) if (rate or per_host) else None  # type: ignore[attr-defined]
    return s


def make_api_session(timeout: float = 40.0, concurrency: int = 30) -> aiohttp.ClientSession:
    ctx = ssl.create_default_context()  # honours SSL_CERT_FILE / system store
    conn = aiohttp.TCPConnector(ssl=ctx, limit=concurrency, limit_per_host=6)
    return aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=timeout),
                                 headers={"User-Agent": "rcn-mstr/1.0 (+recon)"}, trust_env=True)


async def fetch(session: aiohttp.ClientSession, url: str, method: str = "GET", headers: Optional[dict] = None,
                data=None, json_body=None, max_bytes: int = 2_000_000, allow_redirects: bool = False,
                timeout: Optional[float] = None, max_redirects: int = 6, server_hostname: Optional[str] = None
                ) -> Optional[Resp]:
    kw = {}
    if timeout:
        kw["timeout"] = aiohttp.ClientTimeout(total=timeout)
    proxy = getattr(session, "_rcn_proxy", None)
    if proxy:
        kw["proxy"] = proxy
    if server_hostname:
        kw["server_hostname"] = server_hostname
    limiter = getattr(session, "_rcn_limiter", None)
    host = urlparse(url).netloc.split("@")[-1].split(":")[0]
    if limiter:
        await limiter.acquire(host)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    try:
        async with session.request(method, url, headers=headers, data=data, json=json_body,
                                   allow_redirects=allow_redirects, max_redirects=max_redirects, **kw) as r:
            body = await r.content.read(max_bytes)
            hist = [{"url": str(h.url), "status": h.status, "location": h.headers.get("Location", "")}
                    for h in r.history]
            return Resp(str(r.url), r.status, {k.lower(): v for k, v in r.headers.items()},
                        [(k.decode("latin-1"), v.decode("latin-1")) for k, v in r.raw_headers], body, hist,
                        round(loop.time() - t0, 3))
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError, UnicodeError,
            RuntimeError) as e:
        log.debug("fetch %s failed: %s", url, e)
        return None
    finally:
        if limiter:
            limiter.release(host)


async def api_get(session: aiohttp.ClientSession, url: str, params=None, headers=None, retries: int = 2,
                  backoff: float = 2.0, as_json: bool = True, timeout: float = 40.0, method: str = "GET",
                  json_body=None, ok_status=(200,)):
    """GET with retry on 429/5xx/timeouts. Returns parsed JSON / text, or None."""
    last = None
    for attempt in range(retries + 1):
        try:
            async with session.request(method, url, params=params, headers=headers, json=json_body,
                                       timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                if r.status in ok_status:
                    txt = await r.text(errors="replace")
                    if not as_json:
                        return txt
                    try:
                        return json.loads(txt)
                    except ValueError:
                        # some sources return NDJSON
                        out = []
                        for line in txt.splitlines():
                            line = line.strip()
                            if line:
                                try:
                                    out.append(json.loads(line))
                                except ValueError:
                                    pass
                        return out or None
                last = f"HTTP {r.status}"
                if r.status in (429, 500, 502, 503, 504, 520, 522, 524):
                    await asyncio.sleep(backoff * (attempt + 1))
                    continue
                return None
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            last = f"{type(e).__name__}: {e}"
            await asyncio.sleep(backoff * (attempt + 1))
    log.debug("api %s failed: %s", url, last)
    return None
