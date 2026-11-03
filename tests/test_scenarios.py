"""Randomized end-to-end scenario matrix + property sweeps.

Generates many random 'mock internets' with planted issues and drives the real engine over them,
asserting invariants (never crashes, output valid, planted issues surface, no scope violations).
Also runs large property sweeps over the pure helpers (thousands of individual cases).
"""
import asyncio
import json
import os
import random
import string
import tempfile

import pytest

from rcnmstr.context import Config
from rcnmstr.engine import run
from rcnmstr.base import Module
from rcnmstr import permute
from rcnmstr.scope import Scope, clean_host, registrable



def _rand_label(rng, n=None):
    n = n or rng.randint(2, 10)
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=n)).strip("0123456789") or "a"


class _Scenario:
    """A randomly-generated mock org: hosts, HTTP routes, planted issues."""

    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.root = "example.com"
        self.zones = {("google.com", "A"): ["142.250.0.1"], (self.root, "A"): ["127.0.0.1"]}
        self.cnames = {}
        self.wildcards = {}
        self.routes = {"/": (200, {"server": "nginx", "content-type": "text/html"},
                             "<html><title>home</title></html>")}
        self.planted = set()
        self.seed_hosts = [self.root]
        self._build()

    def _build(self):
        rng = self.rng
        nsub = rng.randint(2, 8)
        for _ in range(nsub):
            h = f"{_rand_label(rng)}.{self.root}"
            self.zones[(h, "A")] = ["127.0.0.1"]
            self.seed_hosts.append(h)
        if rng.random() < 0.4:  # wildcard
            self.wildcards[self.root] = ["9.9.9.9"]
            self.planted.add("wildcard")
        if rng.random() < 0.5:  # git leak
            self.routes["/.git/HEAD"] = (200, {}, "ref: refs/heads/main\n")
            self.planted.add("git")
        if rng.random() < 0.5:  # env leak
            self.routes["/.env"] = (200, {}, "SECRET=abc\nDB_PASSWORD=xyz123456\n")
            self.planted.add("env")
        if rng.random() < 0.4:  # secret in JS
            self.routes["/"] = (200, {"content-type": "text/html"},
                                '<html><title>h</title><script src="/a.js"></script></html>')
            self.routes["/a.js"] = (200, {"content-type": "application/javascript"},
                                    'var k="AKIAIOSFODNN7EXAMPLE";var x="ghp_' + "c" * 36 + '";')
            self.planted.add("secret")
        if rng.random() < 0.4:  # CORS reflect+creds
            self.planted.add("cors")
        if rng.random() < 0.5:  # dangling S3 cname
            h = f"shop{rng.randint(1,99)}.{self.root}"
            self.cnames[h] = (f"missing-{_rand_label(rng)}.s3.amazonaws.com", None)
            self.seed_hosts.append(h)
            self.planted.add("takeover")

    def handler(self):
        routes = self.routes
        cors = "cors" in self.planted

        def h(method, path, headers, body):
            p = path.split("?")[0]
            origin = headers.get("origin")
            if cors and origin and p == "/":
                st, hd, b = routes["/"]
                hd = dict(hd)
                hd["access-control-allow-origin"] = origin
                hd["access-control-allow-credentials"] = "true"
                return st, hd, b
            return routes.get(p, (404, {}, "<html><title>404</title>no</html>"))
        return h


async def _mock_dns_server(scn):
    from rcnmstr.dns import wire

    class P(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, data, addr):
            try:
                name, off = wire.read_name(data, 12)
                qt = struct.unpack(">H", data[off:off + 2])[0]
                qtype = wire.qtype_name(qt)
                rrs, rcode = [], 0
                if qtype in ("A", "AAAA") and name in scn.cnames:
                    cur, seen = name, set()
                    while cur in scn.cnames and cur not in seen:
                        seen.add(cur)
                        tgt, fa = scn.cnames[cur]
                        rrs.append(wire.encode_rr(cur, "CNAME", tgt))
                        cur = tgt
                    rcode = 3
                elif (name, qtype) in scn.zones:
                    rrs = [wire.encode_rr(name, qtype, d) for d in scn.zones[(name, qtype)]]
                else:
                    parent = name.split(".", 1)[1] if "." in name else ""
                    if parent in scn.wildcards and qtype == "A":
                        rrs = [wire.encode_rr(name, "A", ip) for ip in scn.wildcards[parent]]
                    elif any(k[0] == name for k in scn.zones):
                        rrs = []
                    else:
                        rcode = 3
                self.t.sendto(wire.build_response(data[:off + 4], rcode=rcode, answers=rrs), addr)
            except Exception:  # noqa
                pass
    import struct
    loop = asyncio.get_running_loop()
    tr, _ = await loop.create_datagram_endpoint(lambda: P(), local_addr=("127.0.0.1", 0))
    return tr, tr.get_extra_info("socket").getsockname()[1]


import struct  # noqa: E402


async def _http_server(scn):
    handler = scn.handler()

    async def conn(reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 4)
            parts = line.decode("latin-1").split()
            method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("GET", "/")
            headers = {}
            while True:
                hl = await asyncio.wait_for(reader.readline(), 4)
                if hl in (b"\r\n", b"\n", b""):
                    break
                k, _, v = hl.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
            if "content-length" in headers:
                try:
                    await asyncio.wait_for(reader.readexactly(int(headers["content-length"])), 4)
                except Exception:  # noqa
                    pass
            status, hd, b = handler(method, path, headers, b"")
            if isinstance(b, str):
                b = b.encode()
            out = f"HTTP/1.1 {status} X\r\n".encode()
            base = {"content-length": str(len(b)), "connection": "close"}
            base.update({k.lower(): v for k, v in hd.items()})
            for k, v in base.items():
                out += f"{k}: {v}\r\n".encode()
            writer.write(out + b"\r\n" + b)
            await writer.drain()
        except Exception:  # noqa
            pass
        finally:
            writer.close()
    srv = await asyncio.start_server(conn, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


@pytest.mark.parametrize("seed", range(40))
async def test_random_scenarios(seed, tmp_path):
    scn = _Scenario(seed)
    dns_tr, dns_port = await _mock_dns_server(scn)
    http_srv, http_port = await _http_server(scn)

    class Seed(Module):
        name = "scnseed"
        mode = "passive"
        phase = 5
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                for h in scn.seed_hosts:
                    ctx.add_host(h, "crtsh")
    cfg = Config(domains=["example.com"], output=str(tmp_path / f"s{seed}"),
                 modules=["scnseed", "resolve", "takeover", "probe", "content", "js", "analysis"],
                 resolvers=[f"127.0.0.1:{dns_port}"], tools=False, brute=False, max_rounds=3,
                 http_ports=[http_port], timeout=3.0, recheck_archive=False)
    try:
        ctx = await run(cfg)
    finally:
        dns_tr.close()
        http_srv.close()

    # ---- invariants that must hold for EVERY scenario ----
    # 1. no scope violations: every host is in scope
    for h in ctx.hosts:
        assert ctx.scope.in_scope(h), f"out-of-scope host leaked: {h}"
    # 2. output is valid + complete
    idx = json.load(open(os.path.join(ctx.outdir, "index.json")))
    assert idx["schema"] == "rcn-mstr/1.1"
    for line in open(os.path.join(ctx.outdir, "findings.jsonl")):
        f = json.loads(line)
        assert f["severity"] in ("info", "low", "medium", "high", "critical")
        assert f["confidence"] in ("tentative", "low", "medium", "high", "confirmed")
    # 3. planted issues surface
    types = {f["type"] for f in ctx.findings.values()}
    if "git" in scn.planted or "env" in scn.planted:
        assert "content_exposure" in types
    if "secret" in scn.planted:
        assert "secret" in types
    if "cors" in scn.planted:
        assert "cors_misconfig" in types
    if "takeover" in scn.planted:
        assert types & {"subdomain_takeover", "dangling_dns"}
    # 4. wildcard hosts, if any planted, are tagged not silently trusted
    if "wildcard" in scn.planted:
        for h, r in ctx.hosts.items():
            if r.get("dns") and r["dns"].get("a") == ["9.9.9.9"]:
                assert "wildcard" in r["tags"]


# ------------------------------------------------------- property sweeps (thousands of cases)
def test_clean_host_never_crashes_fuzz():
    rng = random.Random(7)
    alphabet = string.ascii_letters + string.digits + ".-_:/@*% "
    for _ in range(3000):
        s = "".join(rng.choices(alphabet, k=rng.randint(0, 40)))
        h = clean_host(s)
        if h is not None:
            # a cleaned host must be idempotent and in canonical form
            assert clean_host(h) == h
            assert " " not in h and h == h.lower()


def test_scope_extract_never_out_of_scope():
    rng = random.Random(11)
    s = Scope(["example.com", "test.org"])
    for _ in range(1000):
        words = [f"{_rand_label(rng)}.example.com", f"{_rand_label(rng)}.evil.com",
                 _rand_label(rng), "https://x.test.org/a"]
        rng.shuffle(words)
        text = " ".join(words)
        for h in s.extract_hosts(text):
            assert s.in_scope(h)


def test_permute_sweep_validity():
    rng = random.Random(23)
    words = permute.base_words()[:50]
    for _ in range(300):
        depth = rng.randint(1, 3)
        host = ".".join(_rand_label(rng) for _ in range(depth)) + ".example.com"
        out = permute.permute_host(host, "example.com", words)
        assert host not in out
        for n in list(out)[:200]:
            assert n.endswith(".example.com")
            assert all(0 < len(l) <= 63 for l in n.split("."))


def test_registrable_sweep():
    rng = random.Random(31)
    for _ in range(500):
        depth = rng.randint(0, 4)
        host = ".".join(_rand_label(rng) for _ in range(depth)) + ".example.com"
        reg = registrable(host)
        assert reg.endswith("example.com")
        assert reg.count(".") >= 1
