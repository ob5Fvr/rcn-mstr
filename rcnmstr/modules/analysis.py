"""Correlation engine: derive higher-order findings and an AI-ready attack-surface summary."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List

from ..base import Module

# interesting substrings in a hostname that hint at a juicy target
JUICY = ["admin", "internal", "intranet", "corp", "vpn", "jenkins", "gitlab", "git", "jira", "confluence",
         "grafana", "kibana", "sonar", "nexus", "registry", "staging", "stg", "dev", "test", "uat", "qa",
         "api", "backup", "legacy", "old", "db", "database", "phpmyadmin", "adminer", "console", "dashboard",
         "portal", "manage", "mgmt", "secret", "vault", "sso", "auth", "oauth", "idp", "ldap", "jumpbox",
         "bastion", "rdp", "citrix", "ftp", "sftp", "s3", "status", "monitor", "metrics", "debug", "sandbox"]


class Analysis(Module):
    name = "analysis"
    phase = 90
    mode = "passive"
    final = True
    description = "Correlate signals into prioritised findings and an attack-surface summary"

    async def run(self, ctx):
        self._interesting_hosts(ctx)
        self._cname_only(ctx)
        self._non_cdn_direct(ctx)
        self._tech_cve_hint(ctx)
        self._summary(ctx)

    def _interesting_hosts(self, ctx):
        for h, rec in ctx.hosts.items():
            if not (rec.get("dns") and rec["dns"].get("resolved")) or "wildcard" in rec["tags"]:
                continue
            label = h.split(".")[0]
            hits = [kw for kw in JUICY if kw in h]
            if not hits:
                continue
            direct = not rec.get("cdn")
            has_http = bool(rec.get("http"))
            sev = "low" if (direct and has_http) else "info"
            if any(k in hits for k in ("admin", "internal", "jenkins", "vault", "phpmyadmin", "vpn", "bastion",
                                       "grafana", "kibana")):
                sev = "medium" if direct else "low"
            ctx.finding("interesting_host", sev, "low", h,
                        f"Interesting hostname ({', '.join(sorted(set(hits)))})",
                        {"keywords": sorted(set(hits)), "cdn": rec.get("cdn"), "ips": rec["dns"]["a"],
                         "http": rec.get("http", [])}, self.name, ["triage"] + sorted(set(hits)),
                        dedupe_key=h)

    def _cname_only(self, ctx):
        for h, rec in ctx.hosts.items():
            dns = rec.get("dns")
            if dns and dns.get("cname") and dns.get("cname_target_rcode") in ("SERVFAIL",):
                ctx.finding("dangling_dns", "low", "low", h,
                            "CNAME target returns SERVFAIL (possible dangling/mislinked record)",
                            {"cname": dns["cname"]}, self.name, ["dns"], dedupe_key=h)

    def _non_cdn_direct(self, ctx):
        for h, rec in ctx.hosts.items():
            if rec.get("cdn") or not rec.get("http"):
                continue
            # a host that serves HTTP directly (no CDN) is directly attackable
            ctx.tag_host(h, "direct-origin")

    def _tech_cve_hint(self, ctx):
        for ip, rec in ctx.ips.items():
            idb = rec.get("internetdb")
            if idb and idb.get("vulns") and rec.get("ports"):
                for h in rec["hosts"]:
                    ctx.tag_host(h, "has-cve")

    def _summary(self, ctx):
        hosts = ctx.hosts
        live = ctx.live_hosts()
        cdn = [h for h in live if hosts[h].get("cdn")]
        direct = [h for h in live if not hosts[h].get("cdn")]
        sev_count = Counter(f["severity"] for f in ctx.findings.values())
        type_count = Counter(f["type"] for f in ctx.findings.values())
        tech_count = Counter()
        for s in ctx.services.values():
            for t in s.get("tech", []):
                tech_count[t["name"]] += 1
        asn_count = Counter(r.get("as_name") for r in ctx.ips.values() if r.get("as_name"))
        summary = {
            "roots": ctx.scope.roots,
            "mode": ctx.cfg.mode,
            "dns_mode": ctx.stats.get("dns_mode"),
            "rounds": ctx.round,
            "counts": {
                "hosts_total": len(hosts),
                "hosts_live": len(live),
                "hosts_cdn": len(cdn),
                "hosts_direct": len(direct),
                "hosts_wildcard": sum(1 for r in hosts.values() if "wildcard" in r["tags"]),
                "ips": len(ctx.ips),
                "services": len(ctx.services),
                "findings": len(ctx.findings),
            },
            "findings_by_severity": dict(sev_count),
            "findings_by_type": dict(type_count.most_common()),
            "top_technologies": dict(tech_count.most_common(25)),
            "asns": dict(asn_count.most_common(15)),
            "cdn_vendors": dict(Counter(hosts[h]["cdn"] for h in cdn).most_common()),
            "open_ports": dict(Counter(p for r in ctx.ips.values() for p in r.get("ports", [])).most_common(30)),
            "params_discovered": len(ctx.params),
            "paths_discovered": len(ctx.paths),
            "cloud_refs": sorted(ctx.cloud_refs)[:50],
            "priority_findings": [
                {"id": f["id"], "type": f["type"], "severity": f["severity"], "confidence": f["confidence"],
                 "target": f["target"], "title": f["title"]}
                for f in sorted(ctx.findings.values(),
                                key=lambda x: (-_sev(x["severity"]), -_conf(x["confidence"])))[:40]
            ],
        }
        ctx.stats["summary"] = summary


def _sev(s):
    return ["info", "low", "medium", "high", "critical"].index(s)


def _conf(c):
    return ["tentative", "low", "medium", "high", "confirmed"].index(c)
