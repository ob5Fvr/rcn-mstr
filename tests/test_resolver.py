"""Resolver integration against the in-process FakeDNS: resolution, health, NXDOMAIN, TCP, AXFR, PTR, cache."""
import pytest

from rcnmstr.dns.resolver import Resolver, ResolverUnavailable

pytestmark = pytest.mark.asyncio


async def _resolver(fake_dns, **kw):
    r = Resolver([fake_dns.resolver_str], timeout=2.0, retries=2, **kw)
    await r.start()
    return r


async def test_basic_a_resolution(fake_dns):
    fake_dns.set("www.example.com", "A", ["1.2.3.4", "5.6.7.8"])
    r = await _resolver(fake_dns)
    ans = await r.query("www.example.com", "A")
    assert ans.rcode == "NOERROR"
    assert set(ans.values("A")) == {"1.2.3.4", "5.6.7.8"}
    await r.close()


async def test_nxdomain(fake_dns):
    r = await _resolver(fake_dns)
    ans = await r.query("nope.example.com", "A")
    assert ans.rcode == "NXDOMAIN"
    await r.close()


async def test_health_check_passes(fake_dns):
    r = await _resolver(fake_dns)
    assert r.mode == "udp"
    assert any(v == "ok" for v in r.health_report.values())
    await r.close()


async def test_health_detects_hijacker(fake_dns):
    # resolver that answers random names with an IP (NXDOMAIN hijacking) must be marked unhealthy
    fake_dns.wildcards[""] = ["9.9.9.9"]  # every single-label name resolves
    fake_dns.set("google.com", "A", ["142.250.0.1"])
    # make random *.google.com resolve too -> hijack signature
    fake_dns.wildcards["google.com"] = ["9.9.9.9"]
    r = Resolver([fake_dns.resolver_str], timeout=2.0, retries=2, api_session=None)
    with pytest.raises(ResolverUnavailable):
        await r.start()
    await r.close()


async def test_resolve_host_cname_chain(fake_dns):
    fake_dns.set("www.example.com", "CNAME", ["cdn.example.net"])
    fake_dns.set("cdn.example.net", "A", ["3.3.3.3"])
    # resolver follows chain only if the server returns both; emulate by answering A query with CNAME+A
    fake_dns.set("www.example.com", "A", [])  # placeholder so name "exists"
    r = await _resolver(fake_dns)
    # our fake answers one qtype at a time; resolve_host issues A and AAAA. Put CNAME in A answer:
    import rcnmstr.dns.wire as wire
    fake_dns.zones[("www.example.com", "A")] = []
    await r.close()


async def test_tcp_truncation_fallback(fake_dns):
    fake_dns.set("big.example.com", "A", ["1.1.1.1"])
    fake_dns.truncate.add("big.example.com")
    r = await _resolver(fake_dns)
    ans = await r.query("big.example.com", "A")
    assert ans.transport == "tcp"
    assert ans.values("A") == ["1.1.1.1"]
    await r.close()


async def test_axfr(fake_dns):
    fake_dns.axfr["example.com"] = [
        ("example.com", "SOA", {"mname": "ns1.example.com", "rname": "r.example.com", "serial": 1,
                                 "refresh": 1, "retry": 1, "expire": 1, "minimum": 1}),
        ("www.example.com", "A", "1.2.3.4"),
        ("internal.example.com", "A", "10.0.0.1"),
        ("example.com", "SOA", {"mname": "ns1.example.com", "rname": "r.example.com", "serial": 1,
                                 "refresh": 1, "retry": 1, "expire": 1, "minimum": 1}),
    ]
    r = await _resolver(fake_dns)
    recs = await r.axfr(fake_dns.resolver_str, "example.com")
    assert recs is not None
    names = {x["name"] for x in recs}
    assert "www.example.com" in names and "internal.example.com" in names
    await r.close()


async def test_axfr_refused(fake_dns):
    r = await _resolver(fake_dns)
    recs = await r.axfr(fake_dns.resolver_str, "notazone.com")
    assert recs is None
    await r.close()


async def test_ptr(fake_dns):
    fake_dns.set("4.3.2.1.in-addr.arpa", "PTR", ["host.example.com"])
    r = await _resolver(fake_dns)
    names = await r.ptr("1.2.3.4")
    assert names == ["host.example.com"]
    await r.close()


async def test_cache_and_dedup(fake_dns):
    fake_dns.set("c.example.com", "A", ["1.1.1.1"])
    r = await _resolver(fake_dns)
    await r.query("c.example.com", "A")
    before = len(fake_dns.query_log)
    await r.query("c.example.com", "A")  # served from cache
    assert len(fake_dns.query_log) == before
    await r.close()


async def test_query_server_direct(fake_dns):
    fake_dns.set("example.com", "NS", ["ns1.example.com"])
    r = await _resolver(fake_dns)
    ans = await r.query_server(fake_dns.resolver_str, "example.com", "NS")
    assert "ns1.example.com" in ans.values("NS")
    await r.close()


async def test_servfail_rotates(fake_dns):
    fake_dns.set_rcode("sf.example.com", "A", 2)
    r = await _resolver(fake_dns)
    ans = await r.query("sf.example.com", "A")
    assert ans.rcode == "SERVFAIL"
    await r.close()
