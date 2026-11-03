"""Deep-mode async TCP connect scan + lightweight banner grab on non-CDN IPs."""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

from ..base import Module, gather_limited
from ..util import is_public_ip, is_private_ip

TOP_PORTS = [80, 443, 22, 21, 25, 8080, 8443, 3389, 110, 143, 445, 3306, 5432, 6379, 27017, 9200, 11211,
             8000, 8008, 8081, 8888, 9000, 5000, 5601, 2375, 2376, 23, 53, 135, 139, 389, 636, 1433, 1521,
             5900, 5985, 5986, 7001, 8009, 8161, 9090, 9300, 15672, 16379, 50000, 10250, 2379, 4443, 8443,
             8834, 9043, 9043, 161, 465, 587, 993, 995, 1080, 3000, 4000, 4040, 4848, 5044, 5555, 6060,
             6443, 7000, 7070, 7474, 7687, 8001, 8086, 8140, 8200, 8500, 8880, 9001, 9042, 9092, 9100,
             9418, 9443, 9800, 9999, 10000, 11211, 25565, 26257, 28017, 50070, 2181, 3128, 554, 1900, 102]
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 3306, 6379, 11211, 27017, 9200, 5432, 2375}


class PortScan(Module):
    name = "portscan"
    phase = 45
    mode = "deep"
    description = "TCP connect scan of top ports on unique non-CDN IPs, with unauthenticated banner grab"

    async def run(self, ctx):
        ports = ctx.cfg.scan_ports or TOP_PORTS[: ctx.cfg.top_ports]
        ports = sorted(dict.fromkeys(ports))
        targets = []
        for ip, rec in ctx.ips.items():
            if rec.get("cdn"):
                continue
            allowed_private = ctx.cfg.allow_private and (is_private_ip(ip) or ip.startswith("127."))
            if not is_public_ip(ip) and not allowed_private:
                continue
            if ip in self.done:
                continue
            self.done.add(ip)
            targets.append(ip)
        self.log.info("scanning %d ports on %d IPs", len(ports), len(targets))
        sem = asyncio.Semaphore(ctx.cfg.concurrency * 6)
        for ip in targets:
            results = await gather_limited([self._connect(ip, p, sem, ctx.cfg.timeout) for p in ports],
                                           len(ports))
            open_ports = [p for p in results if p]
            if not open_ports:
                continue
            rec = ctx.ip_rec(ip)
            rec["ports"] = sorted(dict.fromkeys(rec["ports"] + open_ports))
            banners = {}
            for p in open_ports:
                b = await self._banner(ip, p, ctx.cfg.timeout)
                if b:
                    banners[p] = b
                if p in (80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 3000, 5000, 9000, 9090, 8443):
                    scheme = "https" if p in (443, 8443) else "http"
                    for host in rec["hosts"] or [ip]:
                        ctx.web_targets.add((host, p, scheme))
            rec["banners"] = banners
            ctx.emit("portscan", {"ip": ip, "ports": open_ports, "banners": banners, "hosts": rec["hosts"]})
            self._judge(ctx, ip, open_ports, banners, rec)

    async def _connect(self, ip, port, sem, timeout) -> Optional[int]:
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), min(timeout, 4))
                w.close()
                return port
            except (OSError, asyncio.TimeoutError):
                return None

    async def _banner(self, ip, port, timeout) -> Optional[str]:
        probes = {
            6379: b"INFO\r\n", 11211: b"stats\r\n", 27017: b"", 9200: b"GET / HTTP/1.0\r\n\r\n",
            25: b"", 2375: b"GET /version HTTP/1.0\r\n\r\n",
        }
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), min(timeout, 4))
        except (OSError, asyncio.TimeoutError):
            return None
        try:
            if port in probes and probes[port]:
                w.write(probes[port])
                await w.drain()
            data = await asyncio.wait_for(r.read(2048), 4)
            return data.decode("latin-1", "replace").strip()[:1024] or None
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            w.close()

    def _judge(self, ctx, ip, ports, banners, rec):
        risky = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 11211: "Memcached",
                 9200: "Elasticsearch", 2375: "Docker API", 2376: "Docker API", 5984: "CouchDB",
                 9042: "Cassandra", 1433: "MSSQL", 1521: "Oracle", 23: "Telnet", 445: "SMB",
                 3389: "RDP", 5900: "VNC", 10250: "Kubelet", 2379: "etcd"}
        exposed = [(p, risky[p]) for p in ports if p in risky]
        if exposed:
            ctx.finding("exposed_service", "medium", "medium", ip,
                        "Sensitive service(s) exposed: " + ", ".join(f"{s} ({p})" for p, s in exposed),
                        {"ports": ports, "services": dict(exposed), "hosts": rec["hosts"]}, self.name,
                        ["exposure", "ports"], next_steps=["Test for unauthenticated access / default credentials"])
        for p, b in banners.items():
            bl = b.lower()
            if p == 6379 and ("redis_version" in bl or "# server" in bl):
                ctx.finding("exposed_service", "high", "high", f"{ip}:{p}", "Redis responds to unauthenticated INFO",
                            {"banner": b[:300]}, self.name, ["redis", "unauth"])
            if p == 11211 and "stat " in bl:
                ctx.finding("exposed_service", "high", "high", f"{ip}:{p}", "Memcached stats without auth",
                            {"banner": b[:300]}, self.name, ["memcached", "unauth"])
            if p == 9200 and '"cluster_name"' in bl:
                ctx.finding("exposed_service", "high", "high", f"{ip}:{p}", "Elasticsearch open without auth",
                            {"banner": b[:300]}, self.name, ["elasticsearch", "unauth"])
            if p in (2375, 2376) and ("apiversion" in bl or '"version"' in bl.lower()):
                ctx.finding("exposed_service", "critical", "high", f"{ip}:{p}", "Docker API exposed (RCE-prone)",
                            {"banner": b[:300]}, self.name, ["docker", "rce"])
