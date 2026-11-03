"""Async multiplexed stub resolver with health checking, TCP fallback, caching and DoH fallback."""
from __future__ import annotations

import asyncio
import base64
import itertools
import logging
import os
import random
import string
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import wire

log = logging.getLogger("rcnmstr.dns")

DEFAULT_RESOLVERS = [
    "1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "64.6.64.6", "64.6.65.6", "76.76.2.0",
    "76.76.10.0", "94.140.14.140", "185.228.168.9", "8.26.56.26", "77.88.8.8",
]
DOH_ENDPOINTS = ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query",
                 "https://dns.quad9.net/dns-query"]


class ResolverUnavailable(RuntimeError):
    pass


@dataclass
class Answer:
    name: str
    qtype: str
    rcode: str
    answers: List[wire.RR] = field(default_factory=list)
    authority: List[wire.RR] = field(default_factory=list)
    additional: List[wire.RR] = field(default_factory=list)
    server: str = ""
    transport: str = "udp"
    aa: bool = False

    def values(self, rtype: Optional[str] = None) -> list:
        rtype = rtype or self.qtype
        return [r.data for r in self.answers if r.type == rtype]

    @property
    def ok(self) -> bool:
        return self.rcode == "NOERROR"

    def to_dict(self):
        return {"name": self.name, "qtype": self.qtype, "rcode": self.rcode, "server": self.server,
                "answers": [r.to_dict() for r in self.answers]}

    @classmethod
    def from_message(cls, name, qtype, msg: wire.Message, server: str, transport: str) -> "Answer":
        return cls(name, qtype, msg.rcode, msg.answers, msg.authority, msg.additional, server, transport, msg.aa)


def _parse_server(s: str) -> Tuple[str, int]:
    s = s.strip()
    if s.startswith("[") and "]:" in s:
        h, p = s[1:].split("]:")
        return h, int(p)
    if s.count(":") == 1:
        h, p = s.split(":")
        return h, int(p)
    return s, 53


class _UDPChannel(asyncio.DatagramProtocol):
    """One UDP socket per upstream; responses multiplexed by transaction id and validated by question."""

    def __init__(self, addr: Tuple[str, int]):
        self.addr = addr
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.pending: Dict[int, Tuple[asyncio.Future, str, int]] = {}
        self.sent = 0
        self.failures = 0
        self.healthy = True

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) < 12:
            return
        tid = struct.unpack(">H", data[:2])[0]
        entry = self.pending.get(tid)
        if not entry:
            return
        fut, qname, qtype = entry
        try:
            msg = wire.parse_message(data)
        except wire.DNSParseError as e:
            if not fut.done():
                fut.set_exception(e)
            return
        # anti-spoofing / anti-mixup: response question must match
        if not msg.qr or not msg.question or msg.question[0][0] != qname or msg.question[0][1] != qtype:
            return
        self.pending.pop(tid, None)
        if not fut.done():
            fut.set_result(msg)

    def error_received(self, exc):
        log.debug("udp error from %s: %s", self.addr, exc)

    def connection_lost(self, exc):
        for fut, _, _ in self.pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("udp channel closed"))
        self.pending.clear()

    async def query(self, name: str, qtype: str, timeout: float, rd: bool = True) -> wire.Message:
        loop = asyncio.get_running_loop()
        qnum = wire.qtype_num(qtype)
        for _ in range(16):
            tid = random.getrandbits(16)
            if tid not in self.pending:
                break
        else:
            raise RuntimeError("no free transaction ids")
        _, pkt = wire.build_query(name, qtype, tid=tid, rd=rd)
        fut = loop.create_future()
        self.pending[tid] = (fut, wire.normalize(name), qnum)
        try:
            self.transport.sendto(pkt)
            self.sent += 1
            return await asyncio.wait_for(fut, timeout)
        finally:
            self.pending.pop(tid, None)


class Resolver:
    def __init__(self, servers: Optional[List[str]] = None, timeout: float = 2.0, retries: int = 4,
                 concurrency: int = 400, health_name: str = "google.com", api_session=None,
                 doh_endpoints: Optional[List[str]] = None, force_doh: bool = False):
        self.servers = [_parse_server(s) for s in (servers or DEFAULT_RESOLVERS)]
        self.timeout = timeout
        self.retries = retries
        self.sem = asyncio.Semaphore(concurrency)
        self.health_name = health_name
        self.api_session = api_session
        self.doh_endpoints = doh_endpoints or list(DOH_ENDPOINTS)
        self.force_doh = force_doh
        self.channels: List[_UDPChannel] = []
        self.mode = "udp"
        self.cache: Dict[Tuple[str, str], Answer] = {}
        self.inflight: Dict[Tuple[str, str], asyncio.Future] = {}
        self._rr = itertools.count()
        self.stats = {"queries": 0, "cache_hits": 0, "timeouts": 0, "tcp_fallbacks": 0, "doh": 0}
        self.health_report: Dict[str, str] = {}

    # ------------------------------------------------------------------ lifecycle
    async def start(self):
        if not self.force_doh:
            loop = asyncio.get_running_loop()
            for addr in self.servers:
                try:
                    family = 10 if ":" in addr[0] else 2
                    _, proto = await loop.create_datagram_endpoint(
                        lambda a=addr: _UDPChannel(a), remote_addr=addr, family=family)
                    self.channels.append(proto)
                except OSError as e:
                    self.health_report[f"{addr[0]}:{addr[1]}"] = f"socket error: {e}"
            await asyncio.gather(*(self._health(ch) for ch in self.channels))
            healthy = [c for c in self.channels if c.healthy]
            if healthy:
                self.mode = "udp"
                log.info("dns: %d/%d resolvers healthy", len(healthy), len(self.channels))
                return self
            log.warning("dns: no UDP resolver passed health check (%s) -> trying DNS-over-HTTPS",
                        "; ".join(f"{k}={v}" for k, v in self.health_report.items()))
        if self.api_session is None:
            raise ResolverUnavailable("no healthy UDP resolver and no HTTP session for DoH")
        self.mode = "doh"
        good = []
        for ep in self.doh_endpoints:
            if await self._health_doh(ep):
                good.append(ep)
        if not good:
            raise ResolverUnavailable(
                "DNS is unusable: every UDP resolver failed the health check (sinkholed/hijacked/blocked) "
                f"and every DoH endpoint failed ({', '.join(self.doh_endpoints)}). Refusing to continue "
                "because results would be all-NXDOMAIN garbage. Details: " + str(self.health_report))
        self.doh_endpoints = good
        log.warning("dns: using DoH via %s", ", ".join(good))
        return self

    async def close(self):
        for ch in self.channels:
            if ch.transport:
                ch.transport.close()

    def _rand_label(self) -> str:
        return "rcn-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=16))

    async def _health(self, ch: _UDPChannel):
        key = f"{ch.addr[0]}:{ch.addr[1]}"
        try:
            real = await self._udp_with_retry(ch, self.health_name, "A", tries=2)
            if real.rcode != "NOERROR" or not real.records("A"):
                ch.healthy = False
                self.health_report[key] = f"real name {self.health_name} -> {real.rcode}"
                return
            fake = await self._udp_with_retry(ch, f"{self._rand_label()}.{self.health_name}", "A", tries=2)
            if fake.rcode != "NXDOMAIN":
                ch.healthy = False
                self.health_report[key] = f"random name -> {fake.rcode} (hijacking/wildcarding resolver)"
                return
            self.health_report[key] = "ok"
        except Exception as e:  # noqa
            ch.healthy = False
            self.health_report[key] = f"error {type(e).__name__}"

    async def _udp_with_retry(self, ch, name, qtype, tries=2):
        last = None
        for _ in range(tries):
            try:
                return await ch.query(name, qtype, self.timeout)
            except asyncio.TimeoutError as e:
                last = e
        raise last or asyncio.TimeoutError()

    async def _health_doh(self, ep) -> bool:
        try:
            real = await self._doh_query(ep, self.health_name, "A")
            fake = await self._doh_query(ep, f"{self._rand_label()}.{self.health_name}", "A")
            ok = real.rcode == "NOERROR" and bool(real.records("A")) and fake.rcode == "NXDOMAIN"
            self.health_report[ep] = "ok" if ok else f"bad answers {real.rcode}/{fake.rcode}"
            return ok
        except Exception as e:  # noqa
            self.health_report[ep] = f"error {type(e).__name__}: {e}"[:200]
            return False

    # ------------------------------------------------------------------ transports
    async def _doh_query(self, ep: str, name: str, qtype: str) -> wire.Message:
        _, pkt = wire.build_query(name, qtype, tid=0)
        q = base64.urlsafe_b64encode(pkt).rstrip(b"=").decode()
        async with self.api_session.get(ep, params={"dns": q}, headers={"accept": "application/dns-message"},
                                        timeout=_timeout(self.timeout * 3)) as r:
            if r.status != 200:
                raise ConnectionError(f"DoH HTTP {r.status}")
            data = await r.read()
        self.stats["doh"] += 1
        return wire.parse_message(data)

    async def tcp_query(self, server: Tuple[str, int], name: str, qtype: str, rd: bool = True,
                        timeout: Optional[float] = None) -> wire.Message:
        _, pkt = wire.build_query(name, qtype, rd=rd)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server[0], server[1]),
                                                timeout or self.timeout * 2)
        try:
            writer.write(struct.pack(">H", len(pkt)) + pkt)
            await writer.drain()
            ln = struct.unpack(">H", await asyncio.wait_for(reader.readexactly(2), timeout or self.timeout * 2))[0]
            data = await asyncio.wait_for(reader.readexactly(ln), timeout or self.timeout * 2)
            return wire.parse_message(data)
        finally:
            writer.close()

    def _next_channel(self, exclude=()) -> Optional[_UDPChannel]:
        healthy = [c for c in self.channels if c.healthy and c not in exclude] or \
                  [c for c in self.channels if c.healthy]
        if not healthy:
            return None
        return healthy[next(self._rr) % len(healthy)]

    async def _resolve_uncached(self, name: str, qtype: str) -> Answer:
        self.stats["queries"] += 1
        last: Optional[Answer] = None
        if self.mode == "doh":
            for attempt in range(self.retries):
                ep = self.doh_endpoints[attempt % len(self.doh_endpoints)]
                try:
                    msg = await self._doh_query(ep, name, qtype)
                except Exception:  # noqa
                    continue
                ans = Answer.from_message(name, qtype, msg, ep, "doh")
                if ans.rcode in ("SERVFAIL", "REFUSED"):
                    last = ans
                    continue
                return ans
            return last or Answer(name, qtype, "TIMEOUT")
        tried = []
        for attempt in range(self.retries):
            ch = self._next_channel(exclude=tried)
            if ch is None:
                break
            tried.append(ch)
            try:
                msg = await ch.query(name, qtype, self.timeout)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                self.stats["timeouts"] += 1
                ch.failures += 1
                continue
            except wire.DNSParseError:
                continue
            server = f"{ch.addr[0]}:{ch.addr[1]}"
            if msg.tc:
                self.stats["tcp_fallbacks"] += 1
                try:
                    msg = await self.tcp_query(ch.addr, name, qtype)
                    return Answer.from_message(name, qtype, msg, server, "tcp")
                except Exception:  # noqa
                    pass
            ans = Answer.from_message(name, qtype, msg, server, "udp")
            if ans.rcode in ("SERVFAIL", "REFUSED"):
                last = ans
                continue
            return ans
        return last or Answer(name, qtype, "TIMEOUT")

    # ------------------------------------------------------------------ public API
    async def query(self, name: str, qtype: str = "A") -> Answer:
        name = wire.normalize(name)
        qtype = qtype.upper()
        key = (name, qtype)
        if key in self.cache:
            self.stats["cache_hits"] += 1
            return self.cache[key]
        if key in self.inflight:
            return await asyncio.shield(self.inflight[key])
        fut = asyncio.get_running_loop().create_future()
        self.inflight[key] = fut
        try:
            try:
                wire.encode_name(name)
            except ValueError:
                ans = Answer(name, qtype, "BADNAME")
            else:
                async with self.sem:
                    ans = await self._resolve_uncached(name, qtype)
            if ans.rcode != "TIMEOUT":
                self.cache[key] = ans
            fut.set_result(ans)
            return ans
        except BaseException as e:
            if not fut.done():
                fut.set_exception(e)
                fut.exception()  # mark retrieved
            raise
        finally:
            self.inflight.pop(key, None)

    async def resolve_host(self, name: str) -> dict:
        name = wire.normalize(name)
        a, aaaa = await asyncio.gather(self.query(name, "A"), self.query(name, "AAAA"))
        cmap = {}
        for r in a.answers + aaaa.answers:
            if r.type == "CNAME":
                cmap[r.name] = r.data
        chain, cur, seen = [], name, {name}
        while cur in cmap and cmap[cur] not in seen:
            cur = cmap[cur]
            seen.add(cur)
            chain.append(cur)
        ips4 = sorted({r.data for r in a.answers if r.type == "A"})
        ips6 = sorted({r.data for r in aaaa.answers if r.type == "AAAA"})
        rcode = a.rcode if a.rcode != "TIMEOUT" else aaaa.rcode
        target_rcode = None
        if chain:
            if ips4 or ips6:
                target_rcode = "NOERROR"
            elif rcode == "NXDOMAIN":
                target_rcode = "NXDOMAIN"
            else:
                t = await self.query(chain[-1], "A")
                target_rcode = t.rcode
        return {"host": name, "rcode": rcode, "a": ips4, "aaaa": ips6, "cname": chain,
                "cname_target_rcode": target_rcode, "resolved": bool(ips4 or ips6)}

    async def ptr(self, ip: str) -> List[str]:
        ans = await self.query(wire.reverse_name(ip), "PTR")
        return [wire.normalize(x) for x in ans.values("PTR")]

    async def query_server(self, server: str, name: str, qtype: str = "A", rd: bool = False,
                           tcp: bool = False, timeout: float = 3.0) -> Answer:
        """Ask one specific (authoritative) server directly, bypassing cache."""
        addr = _parse_server(server)
        name = wire.normalize(name)
        try:
            if tcp:
                msg = await self.tcp_query(addr, name, qtype, rd=rd, timeout=timeout)
                return Answer.from_message(name, qtype, msg, server, "tcp")
            loop = asyncio.get_running_loop()
            family = 10 if ":" in addr[0] else 2
            transport, proto = await loop.create_datagram_endpoint(lambda: _UDPChannel(addr), remote_addr=addr,
                                                                   family=family)
            try:
                for _ in range(2):
                    try:
                        msg = await proto.query(name, qtype, timeout, rd=rd)
                        break
                    except asyncio.TimeoutError:
                        msg = None
                if msg is None:
                    return Answer(name, qtype, "TIMEOUT", server=server)
                if msg.tc:
                    msg = await self.tcp_query(addr, name, qtype, rd=rd, timeout=timeout)
                return Answer.from_message(name, qtype, msg, server, "udp")
            finally:
                transport.close()
        except (OSError, asyncio.TimeoutError, ConnectionError, wire.DNSParseError) as e:
            return Answer(name, qtype, "TIMEOUT" if isinstance(e, asyncio.TimeoutError) else "ERROR", server=server)

    async def axfr(self, server: str, zone: str, timeout: float = 10.0, max_records: int = 200000):
        """Attempt a zone transfer. Returns list of RR dicts, or None if refused/failed."""
        addr = _parse_server(server)
        _, pkt = wire.build_query(zone, "AXFR", rd=False, edns=False)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(addr[0], addr[1]), timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        records = []
        soa_seen = 0
        try:
            writer.write(struct.pack(">H", len(pkt)) + pkt)
            await writer.drain()
            deadline = time.monotonic() + timeout * 3
            while time.monotonic() < deadline:
                hdr = await asyncio.wait_for(reader.readexactly(2), timeout)
                data = await asyncio.wait_for(reader.readexactly(struct.unpack(">H", hdr)[0]), timeout)
                msg = wire.parse_message(data)
                if msg.rcode != "NOERROR":
                    return None
                if not msg.answers:
                    break
                for rr in msg.answers:
                    records.append(rr.to_dict())
                    if rr.type == "SOA":
                        soa_seen += 1
                if soa_seen >= 2 or len(records) >= max_records:
                    break
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, wire.DNSParseError):
            pass
        finally:
            writer.close()
        return records if soa_seen >= 1 and len(records) > 1 else None


def _timeout(total):
    import aiohttp
    return aiohttp.ClientTimeout(total=total)


def random_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n)) + os.urandom(2).hex()
