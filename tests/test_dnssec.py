"""NSEC/NSEC3 parsing + NSEC zone-walking."""
import struct

import pytest

from rcnmstr.dns import wire
from rcnmstr.dns.resolver import Resolver



def test_type_bitmap_roundtrip():
    types = ["A", "NS", "SOA", "AAAA", "RRSIG", "NSEC", "MX", "TXT"]
    bm = wire.encode_type_bitmap(types)
    assert set(wire._type_bitmap(bm)) == set(types)


def test_base32hex():
    assert wire._b32hex(b"") == ""
    assert wire._b32hex(bytes.fromhex("0123456789")) == "04hkaps9"


def test_nsec_rdata_parse():
    q = wire.build_query("a.example.com", "NSEC")[1][:-11]
    rr = wire.encode_rr("a.example.com", "NSEC", {"next": "b.example.com", "types": ["A", "RRSIG", "NSEC"]})
    msg = wire.parse_message(wire.build_response(q, answers=[rr]))
    data = msg.records("NSEC")[0].data
    assert data["next"] == "b.example.com"
    assert "A" in data["types"] and "NSEC" in data["types"]


async def _resolver(fake_dns, **kw):
    r = Resolver([fake_dns.resolver_str], timeout=2.0, retries=2, **kw)
    await r.start()
    return r


async def test_nsec_walk(fake_dns):
    # chain: example.com -> a.example.com -> b.example.com -> www.example.com -> example.com (wrap)
    chain = {"example.com": "a.example.com", "a.example.com": "b.example.com",
             "b.example.com": "www.example.com", "www.example.com": "example.com"}
    for owner, nxt in chain.items():
        fake_dns.set(owner, "NSEC", [{"next": nxt, "types": ["A", "RRSIG", "NSEC"]}])
    r = await _resolver(fake_dns)
    names, info = await r.nsec_walk("example.com")
    assert info["method"] == "nsec" and info["supported"]
    assert {"a.example.com", "b.example.com", "www.example.com"} <= set(names)
    await r.close()
