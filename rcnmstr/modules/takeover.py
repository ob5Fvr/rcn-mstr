"""Subdomain takeover / dangling DNS: CNAME NXDOMAIN, service fingerprints, unregistered targets, lame NS."""
from __future__ import annotations

import asyncio
import json
import os
import re
from typing import List, Optional

from ..base import Module, gather_limited
from ..http import fetch
from ..scope import registrable

DATA = os.path.join(os.path.dirname(__file__), "..", "data")
FP_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"


def load_fingerprints():
    with open(os.path.join(DATA, "fingerprints.json"), encoding="utf-8") as fh:
        fps = json.load(fh)
    with open(os.path.join(DATA, "takeover_extra.json"), encoding="utf-8") as fh:
        extra = json.load(fh)
    for fp in fps:
        fp["cname"] = [c for c in fp.get("cname") or [] if not c.startswith("http") and not re.match(r"^\d", c)]
        fp["cname"] = list(dict.fromkeys(fp["cname"] + extra["service_cnames"].get(fp["service"], [])))
    return fps, extra


def _host_matches(name: str, pattern: str) -> bool:
    return name == pattern or name.endswith("." + pattern) or (pattern in name and "." not in pattern.strip("-"))


def match_service(chain: List[str], fps) -> List[dict]:
    out = []
    for fp in fps:
        for pat in fp["cname"]:
            if any(_host_matches(c, pat) or pat in c for c in chain):
                out.append(fp)
                break
    return out


def body_matches(fp: dict, status: int, body: str) -> bool:
    f = fp.get("fingerprint") or ""
    if not f or f == "NXDOMAIN":
        return False
    if f.startswith("HTTP_STATUS="):
        try:
            return status == int(f.split("=", 1)[1])
        except ValueError:
            return False
    for alt in [x.strip().strip("`") for x in re.split(r"`\s*`|&#124;", f) if x.strip()]:
        if ".*" in alt or "\\." in alt:
            try:
                if re.search(alt, body):
                    return True
            except re.error:
                pass
        if alt in body:
            return True
    return False


async def update_fingerprints(session) -> int:
    from ..http import api_get
    data = await api_get(session, FP_URL, retries=2)
    if not isinstance(data, list) or not data:
        raise RuntimeError("could not download fingerprints.json")
    with open(os.path.join(DATA, "fingerprints.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    return len(data)


class Takeover(Module):
    name = "takeover"
    phase = 30
    mode = "passive"
    loop = True
    description = "Dangling CNAMEs, service takeover fingerprints, unregistered CNAME/NS targets, lame delegations"

    def __init__(self):
        super().__init__()
        self.fps, self.extra = load_fingerprints()
        self.reg_cache = {}

    async def run(self, ctx):
        todo = [h for h, r in ctx.hosts.items() if r.get("dns") and h not in self.done]
        for h in todo:
            self.done.add(h)
        await gather_limited([self._check(ctx, h) for h in todo], 50)
        # delegations: roots, zones, and SERVFAIL hosts (classic lame delegation symptom)
        deleg = [z for z in list(ctx.scope.roots) + list(ctx.zones) if ("ns:" + z) not in self.done]
        deleg += [h for h in todo if ctx.hosts[h]["dns"]["rcode"] == "SERVFAIL" and ("ns:" + h) not in self.done]
        for z in deleg:
            self.done.add("ns:" + z)
        await gather_limited([self._ns_check(ctx, z) for z in dict.fromkeys(deleg)], 20)

    async def _domain_unregistered(self, ctx, domain: str) -> Optional[bool]:
        reg = registrable(domain)
        if reg in self.reg_cache:
            return self.reg_cache[reg]
        a = await ctx.resolver.query(reg, "NS")
        if a.rcode == "NXDOMAIN":
            soa = await ctx.resolver.query(reg, "SOA")
            val = soa.rcode == "NXDOMAIN"
        elif a.rcode == "NOERROR":
            val = False
        else:
            val = None
        self.reg_cache[reg] = val
        return val

    async def _check(self, ctx, host):
        info = ctx.hosts[host]["dns"]
        chain = info.get("cname") or []
        if not chain:
            return
        target = chain[-1]
        services = match_service(chain, self.fps)
        nx_services = [s for s, pats in self.extra["dns_nxdomain_services"].items()
                       if any(p in c for p in pats for c in chain)]
        ev = {"cname_chain": chain, "rcode": info["rcode"], "target_rcode": info.get("cname_target_rcode")}
        if info.get("cname_target_rcode") == "NXDOMAIN":
            unreg = await self._domain_unregistered(ctx, target)
            if unreg and not ctx.scope.in_scope(target):
                ctx.finding("subdomain_takeover", "high", "high", host,
                            f"CNAME points to unregistered domain {registrable(target)}",
                            {**ev, "unregistered_domain": registrable(target)}, self.name, ["takeover", "dns"],
                            next_steps=[f"Check availability of {registrable(target)} at a registrar and register it"])
                return
            nx_fps = [s for s in services if s.get("nxdomain")]
            if nx_fps or nx_services:
                svc = (nx_fps[0]["service"] if nx_fps else nx_services[0])
                vuln = (nx_fps[0].get("vulnerable") if nx_fps else True)
                ctx.finding("subdomain_takeover", "high" if vuln else "medium", "high" if vuln else "low", host,
                            f"Dangling CNAME to {svc} resource ({target} is NXDOMAIN)",
                            {**ev, "service": svc, "known_vulnerable": vuln}, self.name, ["takeover", "dns", "cloud"],
                            references=[nx_fps[0].get("discussion", "")] if nx_fps else [],
                            next_steps=[f"Try to claim '{target}' in {svc}"])
            else:
                ctx.finding("dangling_dns", "medium" if not ctx.scope.in_scope(target) else "low", "medium", host,
                            f"CNAME target {target} does not resolve (NXDOMAIN)", ev, self.name, ["dns", "dangling"],
                            next_steps=["Identify the provider behind the CNAME target and check if it can be claimed"])
            return
        # resolvable CNAME to a takeover-prone service: verify with HTTP fingerprint
        http_fps = [s for s in services if s.get("fingerprint") and s["fingerprint"] != "NXDOMAIN"]
        if not http_fps or not info.get("resolved"):
            if services:
                ctx.hosts[host].setdefault("services", sorted({s["service"] for s in services}))
            return
        for scheme in ("https", "http"):
            r = await fetch(ctx.probe, f"{scheme}://{host}/", timeout=ctx.cfg.timeout, max_bytes=300000)
            if not r:
                continue
            body = r.text
            for fp in http_fps:
                if body_matches(fp, r.status, body):
                    vuln = bool(fp.get("vulnerable"))
                    ctx.finding("subdomain_takeover", "high" if vuln else "medium", "high" if vuln else "low", host,
                                f"{fp['service']} takeover fingerprint matched",
                                {**ev, "service": fp["service"], "status": r.status, "url": r.url,
                                 "fingerprint": fp["fingerprint"][:200], "status_upstream": fp.get("status")},
                                self.name, ["takeover", "http"], references=[fp.get("discussion", "")],
                                next_steps=[f"Claim the resource on {fp['service']} using {host}"])
                    return
            break

    async def _ns_check(self, ctx, zone):
        """Lame / dangling NS delegation detection by asking the parent zone's authoritative servers."""
        r = ctx.resolver
        ns_names: List[str] = []
        root = ctx.scope.root_of(zone) or zone
        parent_servers = []
        if zone != root and root in ctx.zones:
            parent_servers = [ip for _, ip in ctx.zones[root].get("ns_ips", [])]
        if parent_servers:
            for ip in parent_servers[:3]:
                a = await r.query_server(ip, zone, "NS")
                ns_names = [x.data for x in a.answers + a.authority if x.type == "NS" and x.name == zone]
                if a.rcode in ("NOERROR", "NXDOMAIN"):
                    break
        if not ns_names:
            ns_names = (await r.query(zone, "NS")).values("NS")
        if not ns_names:
            return
        if zone != root:
            ctx.zones.setdefault(zone, {"zone": zone, "delegated": True})
        results = []
        for ns in ns_names:
            ninfo = await r.resolve_host(ns)
            if not ninfo["resolved"]:
                unreg = await self._domain_unregistered(ctx, ns)
                results.append({"ns": ns, "state": "unregistered" if unreg else "nxdomain"})
                continue
            states = []
            for ip in ninfo["a"][:2]:
                a = await r.query_server(ip, zone, "SOA")
                states.append(a.rcode if (a.rcode != "NOERROR" or a.aa or a.values("SOA")) else "NOT_AUTHORITATIVE")
            st = "ok" if "NOERROR" in states else (states[0] if states else "noaddr")
            results.append({"ns": ns, "state": st, "ips": ninfo["a"][:2]})
        lame = [x for x in results if x["state"] != "ok"]
        if not lame:
            return
        unreg = [x for x in results if x["state"] == "unregistered"]
        provider, exploitable = None, False
        for pname, p in self.extra["ns_providers"].items():
            if any(pat in n for pat in p["patterns"] for n in ns_names):
                provider, exploitable = pname, p["exploitable"]
                break
        ev = {"nameservers": results, "provider": provider}
        if unreg:
            ctx.finding("ns_takeover", "critical", "high", zone,
                        f"Nameserver domain is unregistered: {registrable(unreg[0]['ns'])}", ev, self.name,
                        ["takeover", "dns", "ns"],
                        next_steps=[f"Register {registrable(unreg[0]['ns'])} to control DNS for {zone}"])
        elif len(lame) == len(results):
            sev, conf = ("high", "medium") if exploitable else ("medium", "low")
            ctx.finding("ns_takeover", sev, conf, zone,
                        "All delegated nameservers are lame (" + (provider or "unknown provider") + ")", ev,
                        self.name, ["takeover", "dns", "ns"],
                        references=["https://github.com/indianajson/can-i-take-over-dns"],
                        next_steps=["Re-create the zone at " + (provider or "the DNS provider") +
                                    " if the account/zone was deleted"])
        else:
            ctx.finding("dangling_dns", "low", "low", zone,
                        str(len(lame)) + "/" + str(len(results)) + " delegated nameservers do not answer "
                        "authoritatively", ev, self.name, ["dns", "ns"])
        ctx.emit("delegation", {"zone": zone, "result": results, "provider": provider})
