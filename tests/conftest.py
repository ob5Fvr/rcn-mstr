"""Shared test fixtures: in-process fake DNS (UDP+TCP incl. AXFR) and HTTP/HTTPS servers."""
import asyncio
import socket
import ssl
import struct
import tempfile

import pytest

from rcnmstr.dns import wire


class FakeDNS:
    """A tiny authoritative-ish DNS server for tests. zones: {(name, qtype): [rdata,...] | rcode-int}."""

    def __init__(self):
        self.zones = {}
        self.wildcards = {}        # parent -> rdata list for A
        self.nxdomain_random = True
        self.udp_transport = None
        self.tcp_server = None
        self.udp_port = None
        self.tcp_port = None
        self.query_log = []
        self.axfr = {}             # zone -> list of (name, qtype, rdata)
        self.drop = set()          # names to not answer (timeout)
        self.truncate = set()      # names to answer with TC=1 over UDP

    def set(self, name, qtype, rdata):
        self.zones[(wire.normalize(name), qtype)] = rdata

    def set_cname(self, name, target, final_a=None):
        """Model a CNAME: A/AAAA queries return the CNAME RR (+ target A if given), like a real resolver."""
        self.cnames = getattr(self, "cnames", {})
        self.cnames[wire.normalize(name)] = (wire.normalize(target), final_a)

    def set_rcode(self, name, qtype, rcode):
        self.zones[(wire.normalize(name), qtype)] = rcode

    def _answer_for(self, name, qt):
        qtype = wire.qtype_name(qt)
        key = (name, qtype)
        if name in self.drop:
            return None
        if key in self.zones:
            val = self.zones[key]
            if isinstance(val, int):
                return ("rcode", val)
            return ("records", val)
        # wildcard
        parent = name.split(".", 1)[1] if "." in name else ""
        if parent in self.wildcards and qtype == "A":
            return ("records", self.wildcards[parent])
        # known-name fallthrough: NOERROR empty if the name exists for other qtypes
        if any(k[0] == name for k in self.zones):
            return ("records", [])
        return ("rcode", 3)  # NXDOMAIN

    def _build(self, query, tc_ok=True):
        name, off = wire.read_name(query, 12)
        qt = struct.unpack(">H", query[off:off + 2])[0]
        qtype = wire.qtype_name(qt)
        self.query_log.append((name, qtype))
        if name in self.truncate and tc_ok:
            return wire.build_response(query[:off + 4], tc=True)
        cnames = getattr(self, "cnames", {})
        # CNAME chain resolution for A/AAAA
        if qtype in ("A", "AAAA") and name in cnames:
            rrs, cur, seen, final_rcode = [], name, set(), 0
            while cur in cnames and cur not in seen:
                seen.add(cur)
                target, final_a = cnames[cur]
                rrs.append(wire.encode_rr(cur, "CNAME", target))
                cur = target
                if final_a:
                    for ip in (final_a if isinstance(final_a, list) else [final_a]):
                        rrs.append(wire.encode_rr(cur, qtype, ip))
                    return wire.build_response(query[:off + 4], answers=rrs)
            # chain ended without an A; resolve terminal name from zones
            k, v = self._answer_for(cur, qt)
            if k == "records" and v:
                rrs += [wire.encode_rr(cur, qtype, d) for d in v]
                return wire.build_response(query[:off + 4], answers=rrs)
            if k == "rcode":
                return wire.build_response(query[:off + 4], rcode=v, answers=rrs)
            return wire.build_response(query[:off + 4], answers=rrs)
        kind, val = self._answer_for(name, qt) or (None, None)
        if kind is None:
            return None
        if kind == "rcode":
            return wire.build_response(query[:off + 4], rcode=val)
        rrs = [wire.encode_rr(name, qtype, d) for d in val]
        return wire.build_response(query[:off + 4], answers=rrs)

    class _UDP(asyncio.DatagramProtocol):
        def __init__(self, server):
            self.server = server

        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            resp = self.server._build(data)
            if resp is not None:
                self.transport.sendto(resp, addr)

    async def start(self):
        loop = asyncio.get_running_loop()
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: self._UDP(self), local_addr=("127.0.0.1", 0))
        self.udp_port = self.udp_transport.get_extra_info("socket").getsockname()[1]
        # DNS uses the same port number for UDP and TCP; bind TCP to the same port.
        # reuse_address avoids a rare Errno 98 when a freed UDP port's TCP peer is still in TIME_WAIT.
        for attempt in range(5):
            try:
                self.tcp_server = await asyncio.start_server(
                    self._handle_tcp, "127.0.0.1", self.udp_port, reuse_address=True)
                break
            except OSError:
                # the chosen UDP port's TCP side is briefly unavailable; pick a fresh UDP port and retry
                self.udp_transport.close()
                self.udp_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: self._UDP(self), local_addr=("127.0.0.1", 0))
                self.udp_port = self.udp_transport.get_extra_info("socket").getsockname()[1]
        self.tcp_port = self.udp_port
        return self

    async def _handle_tcp(self, reader, writer):
        try:
            while True:
                hdr = await reader.readexactly(2)
                data = await reader.readexactly(struct.unpack(">H", hdr)[0])
                name, off = wire.read_name(data, 12)
                qt = struct.unpack(">H", data[off:off + 2])[0]
                if wire.qtype_name(qt) == "AXFR":
                    await self._axfr(data, name, writer)
                    continue
                resp = self._build(data, tc_ok=False)
                if resp:
                    writer.write(struct.pack(">H", len(resp)) + resp)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def _axfr(self, query, zone, writer):
        if zone not in self.axfr:
            resp = wire.build_response(query[: 12 + len(wire.encode_name(zone)) + 4], rcode=5)
            writer.write(struct.pack(">H", len(resp)) + resp)
            await writer.drain()
            return
        q = query[: 12 + len(wire.encode_name(zone)) + 4]
        rrs = [wire.encode_rr(n, t, d) for n, t, d in self.axfr[zone]]
        resp = wire.build_response(q, answers=rrs)
        writer.write(struct.pack(">H", len(resp)) + resp)
        await writer.drain()

    @property
    def resolver_str(self):
        return f"127.0.0.1:{self.udp_port}"

    async def stop(self):
        if self.udp_transport:
            self.udp_transport.close()
        if self.tcp_server:
            self.tcp_server.close()


@pytest.fixture
async def fake_dns():
    srv = FakeDNS()
    await srv.start()
    # health check names
    srv.set("google.com", "A", ["142.250.0.1"])
    yield srv
    await srv.stop()


class FakeHTTP:
    """Minimal async HTTP/1.1 server. routes: {path: (status, headers_dict, body_bytes_or_str)} or callable."""

    def __init__(self, tls=False):
        self.routes = {}
        self.default = (404, {}, b"not found")
        self.tls = tls
        self.server = None
        self.port = None
        self.host_handler = None   # callable(headers) -> (status, headers, body) override
        self.request_log = []
        self.cert_file = None

    def route(self, path, status=200, headers=None, body=b""):
        self.routes[path] = (status, headers or {}, body if isinstance(body, (bytes, bytearray)) else body.encode())

    async def start(self):
        ssl_ctx = None
        if self.tls:
            ssl_ctx = _self_signed_ctx()
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=ssl_ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 5)
            if not line:
                return
            parts = line.decode("latin-1").split()
            method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("GET", "/")
            headers = {}
            while True:
                h = await asyncio.wait_for(reader.readline(), 5)
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
            body_in = b""
            if "content-length" in headers:
                try:
                    body_in = await asyncio.wait_for(reader.readexactly(int(headers["content-length"])), 5)
                except Exception:  # noqa
                    pass
            self.request_log.append({"method": method, "path": path, "headers": headers, "body": body_in})
            if self.host_handler:
                status, hdrs, body = self.host_handler(method, path, headers, body_in)
            else:
                status, hdrs, body = self.routes.get(path.split("?")[0], self.default)
                if callable(body):
                    status, hdrs, body = body(method, path, headers, body_in)
            if isinstance(body, str):
                body = body.encode()
            out = f"HTTP/1.1 {status} X\r\n".encode()
            base = {"content-length": str(len(body)), "connection": "close"}
            base.update({k.lower(): v for k, v in hdrs.items()})
            for k, v in base.items():
                out += f"{k}: {v}\r\n".encode()
            out += b"\r\n" + body
            writer.write(out)
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def stop(self):
        if self.server:
            self.server.close()


def _self_signed_ctx(hostname="test.local", sans=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    san = x509.SubjectAlternativeName([x509.DNSName(h) for h in (sans or [hostname])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365)).add_extension(san, False)
            .sign(key, hashes.SHA256()))
    cf = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    cf.write(cert.public_bytes(serialization.Encoding.PEM))
    cf.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption()))
    cf.flush()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cf.name)
    return ctx


@pytest.fixture
async def fake_http():
    srv = FakeHTTP()
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture(scope="session")
def selftest_run(tmp_path_factory):
    """Run the full self-test pipeline ONCE per test session; shared read-only by many tests."""
    import asyncio
    from rcnmstr.selftest import run_self_test
    d = str(tmp_path_factory.mktemp("selftest_shared"))
    asyncio.run(run_self_test(d))
    return d
