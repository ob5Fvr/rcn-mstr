"""Takeover DNS paths: unregistered-NS, lame delegation, dangling/NXDOMAIN CNAME, cloud-service CNAME."""
import pytest

from rcnmstr.context import Config
from rcnmstr.engine import run
from rcnmstr.base import Module

pytestmark = pytest.mark.asyncio


def _seed(hosts, name):
    async def _run(self, ctx):
        if ctx.round == 1:
            for h in hosts:
                ctx.add_host(h, "crtsh")
    type("S", (Module,), {"name": name, "mode": "passive", "phase": 5, "default": False, "run": _run})
    return name


async def _run(fake_dns, tmp_path, modules):
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"), modules=modules,
                 resolvers=[fake_dns.resolver_str], tools=False, brute=False, max_rounds=2, timeout=2.0)
    return await run(cfg)


async def test_ns_unregistered_takeover(fake_dns, tmp_path):
    # example.com delegated to a nameserver whose registrable domain is unregistered -> NS takeover
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    fake_dns.set("example.com", "NS", ["ns1.abandoned-zone-xyz.com"])
    # ns host + its registrable both NXDOMAIN (default), so _domain_unregistered -> True
    name = _seed(["example.com"], "nsseed1")
    ctx = await _run(fake_dns, tmp_path, [name, "resolve", "dnsrecords", "takeover"])
    nst = [f for f in ctx.findings.values() if f["type"] == "ns_takeover"]
    assert nst and nst[0]["severity"] == "critical"
    assert "abandoned-zone-xyz.com" in nst[0]["title"]


async def test_dangling_cname_nxdomain(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    # gone.example.com -> CNAME to a non-cloud host that is NXDOMAIN but whose base domain is registered
    fake_dns.set_cname("gone.example.com", "target.stillregistered.com", final_a=None)
    fake_dns.set("stillregistered.com", "NS", ["ns1.stillregistered.com"])  # registered
    name = _seed(["gone.example.com"], "nsseed2")
    ctx = await _run(fake_dns, tmp_path, [name, "resolve", "takeover"])
    dangling = [f for f in ctx.findings.values() if f["type"] in ("dangling_dns", "subdomain_takeover")]
    assert dangling
    assert any(f["target"] == "gone.example.com" for f in dangling)


async def test_cloud_cname_takeover(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    # azure websites NXDOMAIN target -> cloud takeover (NXDOMAIN service) classification
    fake_dns.set_cname("app.example.com", "victim-app.azurewebsites.net", final_a=None)
    name = _seed(["app.example.com"], "nsseed3")
    ctx = await _run(fake_dns, tmp_path, [name, "resolve", "takeover"])
    tk = [f for f in ctx.findings.values() if f["type"] == "subdomain_takeover"]
    assert tk and any("azure" in str(f["evidence"]).lower() or "Azure" in f["title"] for f in tk)


async def test_registered_cname_no_finding(fake_dns, tmp_path):
    # a healthy CNAME to a resolving target must NOT create a takeover finding
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    fake_dns.set_cname("ok.example.com", "cdn.example.net", final_a=["3.3.3.3"])
    name = _seed(["ok.example.com"], "nsseed4")
    ctx = await _run(fake_dns, tmp_path, [name, "resolve", "takeover"])
    tk = [f for f in ctx.findings.values() if f["type"] in ("subdomain_takeover", "dangling_dns")
          and f["target"] == "ok.example.com"]
    assert not tk
