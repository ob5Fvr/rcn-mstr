"""`rcn-mstr --self-test`: run the full pipeline against an in-process mock internet.

This demonstrates every module end-to-end with zero external egress - useful in sandboxed
environments (sinkholed DNS, no outbound) and as a smoke test. It builds a small fake
organisation (example.com) with a takeover, an exposed .git, a leaked AWS key in JS, an open
S3 bucket reference, a CORS misconfig and a dangling CNAME, then runs rcn-mstr against it.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import struct
import sys
import tempfile

from .dns import wire


class _MockDNS(asyncio.DatagramProtocol):
    def __init__(self, zones, cnames, wildcards):
        self.zones, self.cnames, self.wildcards = zones, cnames, wildcards

    def connection_made(self, transport):
        self.transport = transport

    def _answer(self, name, qt):
        qtype = wire.qtype_name(qt)
        if qtype in ("A", "AAAA") and name in self.cnames:
            rrs, cur, seen = [], name, set()
            while cur in self.cnames and cur not in seen:
                seen.add(cur)
                tgt, fa = self.cnames[cur]
                rrs.append(wire.encode_rr(cur, "CNAME", tgt))
                cur = tgt
                if fa:
                    for ip in fa:
                        rrs.append(wire.encode_rr(cur, qtype, ip))
                    return 0, rrs
            if (cur, qtype) in self.zones:
                rrs += [wire.encode_rr(cur, qtype, d) for d in self.zones[(cur, qtype)]]
                return 0, rrs
            return 3, rrs
        if (name, qtype) in self.zones:
            return 0, [wire.encode_rr(name, qtype, d) for d in self.zones[(name, qtype)]]
        parent = name.split(".", 1)[1] if "." in name else ""
        if parent in self.wildcards and qtype == "A":
            return 0, [wire.encode_rr(name, "A", ip) for ip in self.wildcards[parent]]
        if any(k[0] == name for k in self.zones):
            return 0, []
        return 3, []

    def datagram_received(self, data, addr):
        try:
            name, off = wire.read_name(data, 12)
            qt = struct.unpack(">H", data[off:off + 2])[0]
            rcode, rrs = self._answer(name, qt)
            self.transport.sendto(wire.build_response(data[:off + 4], rcode=rcode, answers=rrs), addr)
        except Exception:  # noqa
            pass


def _self_signed(hostnames):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=200))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), False)
            .sign(key, hashes.SHA256()))
    f = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))
    f.flush()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f.name)
    return ctx


ROUTES = {
    "/": (200, {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2", "content-type": "text/html"},
          '<html><head><title>Example Corp</title><meta name="generator" content="WordPress 6.4">'
          '<script src="/static/app.js"></script></head><body><a href="/admin/">admin</a> '
          '<a href="https://api.example.com/">api</a> /wp-content/ login password</body></html>'),
    "/static/app.js": (200, {"content-type": "application/javascript"},
                       'const AWS_KEY="AKIAIOSFODNN7EXAMPLE";'
                       'const token="ghp_' + "b" * 36 + '";'
                       'fetch("/api/v2/internal/users?id=1");'
                       'var internal="https://secret-internal.example.com/";'
                       'var bucket="https://example-corp-backups.s3.amazonaws.com/db.sql";'
                       'var ip="10.0.5.23";'),
    "/.git/HEAD": (200, {}, "ref: refs/heads/main\n"),
    "/.env": (200, {}, "APP_ENV=production\nDB_PASSWORD=sup3rs3cr3t\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
    "/actuator/env": (200, {"content-type": "application/json"},
                      '{"propertySources":[{"name":"systemEnvironment","properties":{"PASSWORD":{"value":"x"}}}]}'),
    "/robots.txt": (200, {}, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"),
}


def _handler_factory(host):
    def handler(method, path, headers, body):
        origin = headers.get("origin")
        p = path.split("?")[0]
        if origin and p == "/":
            st, h, b = ROUTES["/"]
            h = dict(h)
            h["access-control-allow-origin"] = origin
            h["access-control-allow-credentials"] = "true"
            return st, h, b
        return ROUTES.get(p, (404, {}, "<html><title>404 Not Found</title>nope</html>"))
    return handler


async def _http_server(tls, host):
    handler = _handler_factory(host)

    async def _conn(reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 5)
            parts = line.decode("latin-1").split()
            method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("GET", "/")
            headers = {}
            while True:
                h = await asyncio.wait_for(reader.readline(), 5)
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
            if "content-length" in headers:
                try:
                    await asyncio.wait_for(reader.readexactly(int(headers["content-length"])), 5)
                except Exception:  # noqa
                    pass
            status, hdrs, bod = handler(method, path, headers, b"")
            if isinstance(bod, str):
                bod = bod.encode()
            out = f"HTTP/1.1 {status} X\r\n".encode()
            base = {"content-length": str(len(bod)), "connection": "close"}
            base.update({k.lower(): v for k, v in hdrs.items()})
            for k, v in base.items():
                out += f"{k}: {v}\r\n".encode()
            writer.write(out + b"\r\n" + bod)
            await writer.drain()
        except Exception:  # noqa
            pass
        finally:
            writer.close()

    ctx = _self_signed(["example.com", "api.example.com", "www.example.com", "*.example.com"]) if tls else None
    srv = await asyncio.start_server(_conn, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1]


async def run_self_test(outdir: str, modules=None, mode: str = "normal") -> int:
    from .context import Config
    from .engine import run

    http_srv, http_port = await _http_server(False, "example.com")
    loop = asyncio.get_running_loop()

    zones = {
        ("example.com", "A"): ["127.0.0.1"],
        ("www.example.com", "A"): ["127.0.0.1"],
        ("api.example.com", "A"): ["127.0.0.1"],
        ("dev.example.com", "A"): ["127.0.0.1"],
        ("secret-internal.example.com", "A"): ["127.0.0.1"],
        ("example.com", "MX"): [{"preference": 10, "exchange": "mail.example.com"}],
        ("mail.example.com", "A"): ["127.0.0.1"],
        ("example.com", "NS"): ["ns1.example.com"],
        ("ns1.example.com", "A"): ["127.0.0.1"],
        ("example.com", "TXT"): ["v=spf1 include:_spf.google.com +all"],
        ("example.com", "SOA"): [{"mname": "ns1.example.com", "rname": "h.example.com", "serial": 1,
                                   "refresh": 1, "retry": 1, "expire": 1, "minimum": 1}],
        ("google.com", "A"): ["142.250.0.1"],
    }
    cnames = {"shop.example.com": ("missing-bucket.s3.amazonaws.com", None)}
    dns_proto = _MockDNS(zones, cnames, {})
    transport, _ = await loop.create_datagram_endpoint(lambda: dns_proto, local_addr=("127.0.0.1", 0))
    dns_port = transport.get_extra_info("socket").getsockname()[1]

    # seed shop via a scope include so it enters the pipeline (takeover demo)
    sf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    sf.write("example.com\nshop.example.com\n")
    sf.flush()

    default_mods = ["resolve", "dnsrecords", "brute", "permute", "takeover", "probe", "waf", "content", "js",
                    "cloud", "analysis", "correlate"]
    cfg = Config(
        domains=["example.com"], output=outdir, mode=mode,
        modules=modules if modules is not None else default_mods,
        resolvers=[f"127.0.0.1:{dns_port}"], brute=True, tools=False, nuclei=False, max_rounds=3, timeout=3.0,
        http_ports=[http_port], recheck_archive=False, scope_file=sf.name, allow_private=True,
    )
    print(f"[self-test] mock DNS :{dns_port}  mock HTTP :{http_port}  -> {outdir}", file=sys.stderr)
    try:
        ctx = await run(cfg)
    finally:
        transport.close()
        http_srv.close()

    s = ctx.stats.get("summary", {})
    c = s.get("counts", {})
    types = {f["type"] for f in ctx.findings.values()}
    print("\n[self-test] results:", file=sys.stderr)
    print(f"  hosts={c.get('hosts_total')} live={c.get('hosts_live')} services={c.get('services')} "
          f"findings={c.get('findings')}", file=sys.stderr)
    print(f"  finding types: {sorted(types)}", file=sys.stderr)
    print(f"  graph: {ctx.stats.get('graph', {})}", file=sys.stderr)
    print(f"  attack hypotheses: {len(ctx.hypotheses)}", file=sys.stderr)
    for h in ctx.hypotheses[:8]:
        print(f"    [{h['severity']:8}] c={h['confidence']} {h['category']}: {h['title']}", file=sys.stderr)
    expected = {"content_exposure", "secret", "cors_misconfig"}
    missing = expected - types
    ok = not missing and c.get("hosts_live", 0) >= 4 and len(ctx.hypotheses) >= 1
    print(f"  self-test {'PASSED' if ok else 'INCOMPLETE (missing: %s)' % missing}", file=sys.stderr)
    print(f"  output -> {outdir}/index.json", file=sys.stderr)
    return 0 if ok else 1
