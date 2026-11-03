"""Netintel: Cymru parsing, CDN classification, RDAP, InternetDB vuln ingest."""
import pytest

from rcnmstr.modules import netintel as N


def test_classify_helpers():
    assert N.classify_cdn_cname(["d1234.cloudfront.net"]) == "AWS/CloudFront"
    assert N.classify_cdn_cname(["x.akamaiedge.net"]) == "Akamai"
    assert N.classify_cdn_asn("FASTLY, US") == "Fastly"
    assert N.classify_cdn_headers({"x-iinfo": "1"}) == "Imperva"


@pytest.mark.asyncio
async def test_cymru_lookup(fake_dns):
    from rcnmstr.dns.resolver import Resolver
    fake_dns.set("8.8.8.8.origin.asn.cymru.com", "TXT", ["15169 | 8.8.8.0/24 | US | arin | 2000"])
    fake_dns.set("AS15169.asn.cymru.com", "TXT", ["15169 | US | arin | GOOGLE, US"])
    r = Resolver([fake_dns.resolver_str], timeout=2.0, retries=2)
    await r.start()

    class Ctx:
        resolver = r
    res = await N.cymru_lookup(Ctx(), "8.8.8.8")
    assert res["asn"] == "15169" and res["prefix"] == "8.8.8.0/24"
    assert "GOOGLE" in res["as_name"]
    await r.close()


@pytest.mark.asyncio
async def test_netintel_internetdb_vuln(fake_dns, tmp_path, monkeypatch):
    from rcnmstr.context import Config
    from rcnmstr.engine import run
    from rcnmstr.base import Module

    async def fake_api_get(session, url, **kw):
        if "internetdb" in url:
            return {"ports": [22, 443], "cpes": ["cpe:/a:x"], "vulns": ["CVE-2021-1", "CVE-2021-2"],
                    "hostnames": ["found.example.com"], "tags": []}
        return None
    monkeypatch.setattr(N, "api_get", fake_api_get)
    fake_dns.set("h.example.com", "A", ["44.44.44.44"])
    fake_dns.set("44.44.44.44.origin.asn.cymru.com", "TXT", ["99 | 44.44.44.0/24 | US | arin | x"])

    class Seed(Module):
        name = "niseed"; mode = "passive"; phase = 5; default = False
        async def run(self, ctx):
            if ctx.round == 1:
                ctx.add_host("h.example.com", "crtsh")
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"), modules=["niseed", "resolve", "netintel"],
                 resolvers=[fake_dns.resolver_str], tools=False, brute=False, max_rounds=2, timeout=2.0)
    ctx = await run(cfg)
    rec = ctx.ips.get("44.44.44.44")
    assert rec and rec["internetdb"]["vulns"] == ["CVE-2021-1", "CVE-2021-2"]
    assert "found.example.com" in ctx.hosts   # hostname fed back
    assert any(f["type"] == "known_vulns" for f in ctx.findings.values())
