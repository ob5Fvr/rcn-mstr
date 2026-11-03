"""Origin-IP discovery behind a CDN, verified by Host-header + body simhash."""
import asyncio

import pytest

from rcnmstr.context import Config
from rcnmstr.engine import run
from rcnmstr.base import Module


@pytest.mark.asyncio
async def test_origin_ip_discovered(fake_dns, tmp_path):
    # app.example.com is "CDN-fronted"; origin 127.0.0.1 serves the same body with the right Host.
    body = b"<html><title>Acme App</title>welcome to acme dashboard with lots of unique content here</title></html>"

    async def origin(reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 3)
            headers = {}
            while True:
                h = await asyncio.wait_for(reader.readline(), 3)
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
            # only serve the app when Host matches (origin behind CDN keyed by vhost)
            if headers.get("host", "").startswith("app.example.com"):
                b, st = body, 200
            else:
                b, st = b"<html><title>default</title>nothing</html>", 404
            out = (f"HTTP/1.1 {st} X\r\ncontent-length: {len(b)}\r\nconnection: close\r\n\r\n").encode() + b
            writer.write(out)
            await writer.drain()
        except Exception:  # noqa
            pass
        finally:
            writer.close()
    srv = await asyncio.start_server(origin, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]

    # DNS: app.example.com -> a "CDN" IP; a sibling non-CDN host resolves to 127.0.0.1 (origin candidate)
    fake_dns.set("app.example.com", "A", ["127.0.0.1"])   # probe hits origin directly via http_ports
    fake_dns.set("sib.example.com", "A", ["127.0.0.1"])

    class Seed(Module):
        name = "oseed"
        mode = "passive"
        phase = 5
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                ctx.add_host("app.example.com", "crtsh")
                ctx.add_host("sib.example.com", "crtsh")

    class MarkCdn(Module):
        name = "markcdn"
        mode = "passive"
        phase = 48  # after netintel-ish; before origin(55)
        default = False
        loop = True

        async def run(self, ctx):
            if "app.example.com" in ctx.hosts and ctx.hosts["app.example.com"].get("dns"):
                ctx.hosts["app.example.com"]["cdn"] = "Cloudflare"

    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=["oseed", "resolve", "markcdn", "probe", "origin"],
                 resolvers=[fake_dns.resolver_str], tools=False, brute=False, max_rounds=2,
                 http_ports=[port], timeout=3.0, allow_private=True)
    try:
        ctx = await run(cfg)
    finally:
        srv.close()
    origin_findings = [f for f in ctx.findings.values() if f["type"] == "origin_ip_exposure"]
    assert origin_findings, "expected an origin_ip_exposure finding"
    assert "127.0.0.1" in origin_findings[0]["evidence"]["ip"]


def test_origin_candidate_gathering():
    # unit: _candidates pulls non-CDN public IPs, excludes CDN-range IPs
    from rcnmstr.modules.origin import OriginIP

    class Ctx:
        def __init__(self):
            self.ips = {"5.6.7.8": {"ip": "5.6.7.8", "cdn": None},
                        "104.16.1.1": {"ip": "104.16.1.1", "cdn": "Cloudflare"},
                        "9.9.9.9": {"ip": "9.9.9.9", "cdn": None}}
            self.stats = {"spf_ips": {"example.com": ["1.2.3.4"]}}
            self.zones = {}
            self.hosts = {}

            class C:
                allow_private = False
            self.cfg = C()
    cands = OriginIP()._candidates(Ctx())
    assert "5.6.7.8" in cands and "9.9.9.9" in cands
    assert "104.16.1.1" not in cands        # CDN tagged
    assert "1.2.3.4" in cands               # from SPF ip4


@pytest.mark.asyncio
async def test_api_candidates_shodan_censys(monkeypatch):
    import rcnmstr.modules.origin as O

    async def fake_api_get(session, url, params=None, headers=None, **kw):
        if "api.shodan.io" in url:
            return {"matches": [{"ip_str": "11.22.33.44"}, {"ip_str": "55.66.77.88"}]}
        if "censys.io" in url:
            return {"result": {"hits": [{"ip": "99.88.77.66"}]}}
        return None
    monkeypatch.setattr(O, "api_get", fake_api_get)

    class Ctx:
        def __init__(self):
            self.services = {"https://x": {"favicon_mmh3": 12345}}
            self.api = object()

            class S:
                roots = ["example.com"]
            self.scope = S()
            self._keys = {"shodan_key": "k", "censys_id": "i", "censys_secret": "s"}

        def key(self, n):
            return self._keys.get(n)
    cands = await O.OriginIP()._api_candidates(Ctx())
    assert {"11.22.33.44", "55.66.77.88", "99.88.77.66"} <= cands


@pytest.mark.asyncio
async def test_api_candidates_no_keys():
    from rcnmstr.modules.origin import OriginIP

    class Ctx:
        services = {}
        api = object()

        class scope:
            roots = ["example.com"]

        def key(self, n):
            return None
    assert await OriginIP()._api_candidates(Ctx()) == set()
