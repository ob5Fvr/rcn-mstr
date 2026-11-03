"""Related-domain (cert-cluster) discovery and nuclei ingest."""
import asyncio

import pytest

from rcnmstr.context import Config
from rcnmstr.engine import run
from rcnmstr.base import Module

pytestmark_async = pytest.mark.asyncio


def _seed(hosts, services_tls, name="relseed"):
    async def _run(self, ctx):
        if ctx.round == 1:
            for h in hosts:
                ctx.add_host(h, "crtsh")
                ctx.hosts[h]["dns"] = {"resolved": True, "a": ["127.0.0.1"], "aaaa": [], "cname": []}
            for url, tls in services_tls:
                host = url.split("://")[1].split("/")[0]
                ctx.services[url] = {"url": url, "host": host, "scheme": "https", "port": 443,
                                     "status": 200, "title": "t", "tech": [], "tls": tls, "simhash": 1}
    # name must be set in the class body so __init_subclass__ registers it
    Seed = type("Seed", (Module,), {"name": name, "mode": "passive", "phase": 49, "default": False,
                                    "run": _run})
    return name


@pytest.mark.asyncio
async def test_related_domain_from_shared_cert(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    tls = {"fingerprint_sha256": "FP1", "common_name": "example.com",
           "sans": ["example.com", "www.example.com", "acme-corp.net", "acme-corp.io"]}
    name = _seed(["example.com"], [("https://example.com", tls)])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=[name, "resolve", "related"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, max_rounds=2, timeout=3.0)
    ctx = await run(cfg)
    rel = [f for f in ctx.findings.values() if f["type"] == "related_domain"]
    domains = {f["evidence"]["domain"] for f in rel}
    assert "acme-corp.net" in domains and "acme-corp.io" in domains
    # not expanded unless flag set
    assert "acme-corp.net" not in ctx.scope.roots


@pytest.mark.asyncio
async def test_related_domain_scope_expansion(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    tls = {"fingerprint_sha256": "FP2", "common_name": "example.com",
           "sans": ["example.com", "sibling-brand.com"]}
    name = _seed(["example.com"], [("https://example.com", tls)])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=[name, "resolve", "related"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, max_rounds=2, timeout=3.0, expand_scope=True)
    ctx = await run(cfg)
    assert "sibling-brand.com" in ctx.scope.roots
    assert ctx.scope.in_scope("sibling-brand.com")


@pytest.mark.asyncio
async def test_related_ignores_unrelated_cert(fake_dns, tmp_path):
    # a cert that does NOT cover any owned domain must not create related findings
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    tls = {"fingerprint_sha256": "FP3", "common_name": "other.com", "sans": ["other.com", "unrelated.net"]}
    name = _seed(["example.com"], [("https://example.com", tls)])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=[name, "resolve", "related"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, max_rounds=2, timeout=3.0)
    ctx = await run(cfg)
    rel = [f for f in ctx.findings.values() if f["type"] == "related_domain"]
    assert not rel


# ------------------------------------------------------------- nuclei ingest (pure)
def test_nuclei_ingest():
    from rcnmstr.modules.nuclei import Nuclei

    class Ctx:
        def __init__(self):
            self.findings = {}
            self.emitted = []

        def emit(self, k, o):
            self.emitted.append((k, o))

        def finding(self, *a, **k):
            self.findings[a[0] + a[3]] = (a, k)
    c = Ctx()
    n = Nuclei()
    r = {"template-id": "CVE-2021-1234", "info": {"name": "Example RCE", "severity": "critical",
         "tags": ["cve", "rce"]}, "matched-at": "https://x.example.com/vuln", "type": "http"}
    assert n._ingest(c, r) == 1
    assert c.emitted and c.emitted[0][0] == "nuclei"
    (args, kw) = list(c.findings.values())[0]
    assert args[0] == "nuclei" and args[1] == "critical"


@pytest.mark.asyncio
async def test_nuclei_skipped_without_binary(fake_dns, tmp_path, monkeypatch):
    import rcnmstr.modules.nuclei as nm
    monkeypatch.setattr(nm.shutil, "which", lambda x: None)
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"), modules=["resolve", "nuclei"],
                 resolvers=[fake_dns.resolver_str], tools=False, brute=False, mode="deep",
                 nuclei=True, max_rounds=1, timeout=2.0)
    ctx = await run(cfg)  # must not crash
    assert "nuclei" not in {f["type"] for f in ctx.findings.values()}
