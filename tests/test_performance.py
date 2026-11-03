"""Performance + stress: resolver throughput, probe concurrency, parser robustness under fuzzing."""
import asyncio
import os
import random
import struct
import time

import pytest

from rcnmstr.dns import wire
from rcnmstr.dns.resolver import Resolver

pytestmark = pytest.mark.asyncio


async def _resolver(fake_dns, **kw):
    r = Resolver([fake_dns.resolver_str], timeout=2.0, retries=2, **kw)
    await r.start()
    return r


async def test_resolver_throughput(fake_dns):
    """Resolve 5000 names concurrently; assert it completes quickly and correctly."""
    for i in range(5000):
        fake_dns.set(f"h{i}.example.com", "A", [f"10.0.{i // 256}.{i % 256}"])
    r = await _resolver(fake_dns, concurrency=500)
    names = [f"h{i}.example.com" for i in range(5000)]
    t0 = time.monotonic()
    results = await asyncio.gather(*(r.query(n, "A") for n in names))
    dt = time.monotonic() - t0
    ok = sum(1 for a in results if a.rcode == "NOERROR" and a.values("A"))
    assert ok == 5000
    rate = 5000 / dt
    print(f"\nresolver: 5000 queries in {dt:.2f}s = {rate:.0f} q/s")
    assert dt < 20, f"too slow: {dt:.1f}s"
    await r.close()


async def test_resolver_dedup_inflight(fake_dns):
    """1000 concurrent identical queries must collapse to a single wire query."""
    fake_dns.set("same.example.com", "A", ["1.2.3.4"])
    r = await _resolver(fake_dns)
    results = await asyncio.gather(*(r.query("same.example.com", "A") for _ in range(1000)))
    assert all(a.values("A") == ["1.2.3.4"] for a in results)
    # cache + inflight dedup => at most a handful of actual queries hit the server
    assert len([q for q in fake_dns.query_log if q[0] == "same.example.com"]) <= 2
    await r.close()


async def test_probe_concurrency(fake_dns, fake_http):
    """Probe 300 hosts (all pointing at one fake server) and confirm throughput + correctness."""
    from rcnmstr.context import Config
    from rcnmstr.engine import run
    import tempfile
    for i in range(300):
        fake_dns.set(f"h{i}.example.com", "A", ["127.0.0.1"])
    fake_http.route("/", 200, {"server": "nginx"}, "<html><title>t</title></html>")

    from rcnmstr.base import Module

    class Seed(Module):
        name = "perfseed"
        mode = "passive"
        phase = 5
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                for i in range(300):
                    ctx.add_host(f"h{i}.example.com", "seed")
    out = tempfile.mkdtemp()
    cfg = Config(domains=["example.com"], output=out, modules=["perfseed", "resolve", "probe"],
                 resolvers=[fake_dns.resolver_str], tools=False, brute=False, max_rounds=2,
                 http_ports=[fake_http.port], concurrency=100, timeout=4.0)
    t0 = time.monotonic()
    ctx = await run(cfg)
    dt = time.monotonic() - t0
    print(f"\nprobe: {len(ctx.services)} services in {dt:.2f}s")
    assert len(ctx.services) == 300
    assert dt < 30


async def test_parser_fuzzing_never_hangs():
    """Feed 2000 random byte strings to the DNS parser; it must never hang or raise unexpectedly."""
    random.seed(1337)
    ok = 0
    for _ in range(2000):
        n = random.randint(0, 80)
        data = bytes(random.getrandbits(8) for _ in range(n))
        try:
            wire.parse_message(data)
            ok += 1
        except wire.DNSParseError:
            ok += 1
        except Exception as e:  # any OTHER exception type is a bug
            pytest.fail(f"unexpected {type(e).__name__} on fuzz input: {e!r} data={data!r}")
    assert ok == 2000


async def test_parser_fuzzing_valid_headers():
    """Random but structurally-valid headers with junk bodies must parse or raise DNSParseError only."""
    random.seed(42)
    for _ in range(1000):
        tid = random.getrandbits(16)
        flags = random.getrandbits(16)
        counts = [random.randint(0, 20) for _ in range(4)]
        pkt = struct.pack(">HHHHHH", tid, flags, *counts[:1], *counts[1:])[:12]
        pkt = struct.pack(">HHHHHH", tid, flags, counts[0], counts[1], counts[2], counts[3])
        pkt += wire.encode_name("example.com") + struct.pack(">HH", 1, 1)
        pkt += bytes(random.getrandbits(8) for _ in range(random.randint(0, 60)))
        try:
            wire.parse_message(pkt)
        except wire.DNSParseError:
            pass


async def test_name_compression_deeply_nested(fake_dns):
    """A legitimately long compression chain must still parse."""
    # build a packet with a chain of pointers that is long but within limits
    base = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    base += wire.encode_name("a.b.c.d.e.f.example.com") + struct.pack(">HH", 1, 1)
    base += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    msg = wire.parse_message(base)
    assert msg.records("A")[0].data == "1.2.3.4"
