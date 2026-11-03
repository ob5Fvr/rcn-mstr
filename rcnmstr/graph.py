"""Correlation knowledge graph.

Turns the flat recon tables (hosts, ips, services, findings, ...) into a typed entity/edge graph
and derives clusters that reveal structure no flat list shows: which assets share a TLS certificate,
which services are the same app (favicon / body / tech), which IP co-hosts many names, which assets
live on org-owned netblocks vs. CDN edges.

This graph is the substrate the attack-hypothesis engine reasons over, and it is emitted raw
(nodes.jsonl / edges.jsonl / graph.dot) for a downstream AI harness to traverse.

Pure and deterministic: `build_graph` takes a Context-like object and returns a Graph.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .util import hamming


def nid(ntype: str, key: str) -> str:
    return f"{ntype}:{key}"


@dataclass
class Node:
    id: str
    type: str
    label: str
    attrs: dict = field(default_factory=dict)

    def to_dict(self):
        return {"id": self.id, "type": self.type, "label": self.label, **self.attrs}


@dataclass
class Edge:
    src: str
    dst: str
    type: str
    attrs: dict = field(default_factory=dict)

    def key(self):
        return (self.src, self.dst, self.type)

    def to_dict(self):
        return {"src": self.src, "dst": self.dst, "type": self.type, **self.attrs}


class Graph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str, str], Edge] = {}
        self.adj: Dict[str, Set[str]] = defaultdict(set)
        self.radj: Dict[str, Set[str]] = defaultdict(set)

    def add_node(self, ntype: str, key: str, label: Optional[str] = None, **attrs) -> str:
        i = nid(ntype, key)
        n = self.nodes.get(i)
        if n is None:
            self.nodes[i] = Node(i, ntype, label or key, dict(attrs))
        else:
            n.attrs.update({k: v for k, v in attrs.items() if v is not None})
        return i

    def add_edge(self, src: str, dst: str, etype: str, **attrs):
        if src not in self.nodes or dst not in self.nodes:
            return
        k = (src, dst, etype)
        if k in self.edges:
            self.edges[k].attrs.update(attrs)
        else:
            self.edges[k] = Edge(src, dst, etype, dict(attrs))
            self.adj[src].add(dst)
            self.radj[dst].add(src)

    def neighbors(self, i: str, etype: Optional[str] = None, out: bool = True) -> List[str]:
        base = self.adj if out else self.radj
        if etype is None:
            return sorted(base.get(i, ()))
        res = []
        for other in base.get(i, ()):
            key = (i, other, etype) if out else (other, i, etype)
            if key in self.edges:
                res.append(other)
        return sorted(res)

    def nodes_of(self, ntype: str) -> List[Node]:
        return [n for n in self.nodes.values() if n.type == ntype]

    # ---------------------------------------------------------------- serialization
    def to_jsonl(self) -> Tuple[List[dict], List[dict]]:
        return ([n.to_dict() for n in self.nodes.values()],
                [e.to_dict() for e in self.edges.values()])

    def to_dot(self, max_nodes: int = 4000) -> str:
        colors = {"host": "#4f9", "ip": "#49f", "asn": "#f94", "cert": "#9f4", "favicon": "#f49",
                  "tech": "#ccc", "bucket": "#fc4", "finding": "#f44", "service": "#9cf",
                  "cluster": "#c9f", "netblock": "#fa7"}
        out = ["digraph recon {", '  rankdir=LR; node [style=filled,fontsize=9,shape=box];']
        for i, n in enumerate(self.nodes.values()):
            if i >= max_nodes:
                break
            lbl = n.label.replace('"', "'")[:40]
            out.append(f'  "{n.id}" [label="{lbl}",fillcolor="{colors.get(n.type, "#eee")}"];')
        shown = set(list(self.nodes)[:max_nodes])
        for e in self.edges.values():
            if e.src in shown and e.dst in shown:
                out.append(f'  "{e.src}" -> "{e.dst}" [label="{e.type}",fontsize=7];')
        out.append("}")
        return "\n".join(out)

    def stats(self) -> dict:
        nt = defaultdict(int)
        for n in self.nodes.values():
            nt[n.type] += 1
        et = defaultdict(int)
        for e in self.edges.values():
            et[e.type] += 1
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "node_types": dict(nt), "edge_types": dict(et)}


# ------------------------------------------------------------------ building


def build_graph(ctx) -> Graph:
    g = Graph()
    # hosts + dns
    for host, rec in ctx.hosts.items():
        dns = rec.get("dns") or {}
        g.add_node("host", host, host, resolved=dns.get("resolved", False), cdn=rec.get("cdn"),
                   tags=rec.get("tags", []), sources=rec.get("sources", []), waf=rec.get("waf"))
        for ip in dns.get("a", []) + dns.get("aaaa", []):
            g.add_node("ip", ip, ip)
            g.add_edge(nid("host", host), nid("ip", ip), "resolves_to")
        for c in dns.get("cname", []):
            g.add_node("host", c, c) if ctx.scope.in_scope(c) else g.add_node("cname_target", c, c)
            tgt = nid("host", c) if ctx.scope.in_scope(c) else nid("cname_target", c)
            g.add_edge(nid("host", host), tgt, "cname")
    # ips + asn + netblock
    for ip, rec in ctx.ips.items():
        g.add_node("ip", ip, ip, asn=rec.get("asn"), as_name=rec.get("as_name"), cdn=rec.get("cdn"),
                   ptr=rec.get("ptr", []), ports=rec.get("ports", []),
                   vulns=(rec.get("internetdb") or {}).get("vulns", []))
        if rec.get("asn"):
            g.add_node("asn", rec["asn"], f"AS{rec['asn']} {rec.get('as_name') or ''}".strip(),
                       as_name=rec.get("as_name"), cdn=bool(rec.get("cdn")))
            g.add_edge(nid("ip", ip), nid("asn", rec["asn"]), "in_asn")
        if rec.get("prefix"):
            g.add_node("netblock", rec["prefix"], rec["prefix"])
            g.add_edge(nid("ip", ip), nid("netblock", rec["prefix"]), "in_netblock")
    # services + cert + favicon + tech
    for url, svc in ctx.services.items():
        host = svc.get("host")
        g.add_node("service", url, url, status=svc.get("status"), title=svc.get("title"),
                   server=svc.get("server"), simhash=svc.get("simhash"), waf=bool(svc.get("waf")))
        if host:
            g.add_edge(nid("service", url), nid("host", host), "serves")
        tls = svc.get("tls")
        if tls and tls.get("fingerprint_sha256"):
            fp = tls["fingerprint_sha256"]
            g.add_node("cert", fp, (tls.get("common_name") or fp)[:40], issuer=tls.get("issuer_cn"),
                       sans=tls.get("sans", []), not_after=tls.get("not_after"))
            g.add_edge(nid("service", url), nid("cert", fp), "presents_cert")
            for san in tls.get("sans", []):
                san = san.lstrip("*.").lower()
                if san in ctx.hosts:
                    g.add_edge(nid("cert", fp), nid("host", san), "covers")
        if svc.get("favicon_mmh3"):
            fh = str(svc["favicon_mmh3"])
            g.add_node("favicon", fh, f"favicon {fh}")
            g.add_edge(nid("service", url), nid("favicon", fh), "has_favicon")
        for t in svc.get("tech", []):
            g.add_node("tech", t["name"], t["name"], category=t.get("category"))
            g.add_edge(nid("service", url), nid("tech", t["name"]), "runs")
    # buckets & findings
    for f in ctx.findings.values():
        g.add_node("finding", f["id"], f["title"][:50], ftype=f["type"], severity=f["severity"],
                   confidence=f["confidence"])
        tgt = f["target"]
        for cand in (nid("service", tgt), nid("host", tgt), nid("ip", tgt),
                     nid("host", tgt.split("/")[2]) if "://" in tgt else None):
            if cand and cand in g.nodes:
                g.add_edge(nid("finding", f["id"]), cand, "about")
                break
    return g


# ------------------------------------------------------------------ clustering


def _components(members: Iterable[str], shared: Dict[str, List[str]]) -> List[List[str]]:
    """Group members by any shared key (e.g. cert fp, favicon)."""
    clusters = []
    for key, items in shared.items():
        if len(items) > 1:
            clusters.append(sorted(set(items)))
    return clusters


def cert_clusters(g: Graph) -> List[dict]:
    out = []
    for cert in g.nodes_of("cert"):
        hosts = sorted({n.split(":", 1)[1] for n in g.neighbors(cert.id, "covers")})
        services = sorted({n.split(":", 1)[1] for n in g.neighbors(cert.id, "presents_cert", out=False)})
        hosts = sorted(set(hosts) | {s.split("://")[1].split(":")[0].split("/")[0] for s in services if "://" in s})
        if len(hosts) > 1:
            out.append({"cert": cert.id.split(":", 1)[1], "cn": cert.label, "hosts": hosts,
                        "sans": cert.attrs.get("sans", [])})
    return out


def favicon_clusters(ctx) -> List[dict]:
    by_hash: Dict[str, List[str]] = defaultdict(list)
    for url, svc in ctx.services.items():
        if svc.get("favicon_mmh3"):
            by_hash[str(svc["favicon_mmh3"])].append(url)
    return [{"favicon_mmh3": h, "services": sorted(v)} for h, v in by_hash.items() if len(v) > 1]


def simhash_clusters(ctx, threshold: int = 6) -> List[dict]:
    items = [(url, svc) for url, svc in ctx.services.items() if svc.get("simhash")]
    used = set()
    clusters = []
    for i, (u1, s1) in enumerate(items):
        if u1 in used:
            continue
        group = [(u1, s1)]
        used.add(u1)
        for u2, s2 in items[i + 1:]:
            if u2 in used:
                continue
            if hamming(s1["simhash"], s2["simhash"]) <= threshold:
                group.append((u2, s2))
                used.add(u2)
        if len(group) > 1:
            statuses = {u: s["status"] for u, s in group}
            clusters.append({"size": len(group), "services": sorted(statuses),
                             "statuses": statuses,
                             "distinct_statuses": sorted(set(statuses.values()))})
    return clusters


def cohosted_ips(g: Graph, min_hosts: int = 3) -> List[dict]:
    out = []
    for ip in g.nodes_of("ip"):
        hosts = sorted({n.split(":", 1)[1] for n in g.neighbors(ip.id, "resolves_to", out=False)})
        if len(hosts) >= min_hosts and not ip.attrs.get("cdn"):
            out.append({"ip": ip.id.split(":", 1)[1], "hosts": hosts, "asn": ip.attrs.get("asn"),
                        "as_name": ip.attrs.get("as_name")})
    return out


def org_asn_assets(g: Graph, keywords: List[str]) -> List[dict]:
    out = []
    for asn in g.nodes_of("asn"):
        name = (asn.attrs.get("as_name") or "").lower()
        if asn.attrs.get("cdn"):
            continue
        owned = any(k in name for k in keywords)
        ips = sorted({n.split(":", 1)[1] for n in g.neighbors(asn.id, "in_asn", out=False)})
        if owned and ips:
            hosts = sorted({h.split(":", 1)[1] for ip in ips
                            for h in g.neighbors(nid("ip", ip), "resolves_to", out=False)})
            out.append({"asn": asn.id.split(":", 1)[1], "as_name": asn.attrs.get("as_name"),
                        "ips": ips, "hosts": hosts})
    return out


def all_clusters(ctx, g: Graph) -> dict:
    return {
        "cert": cert_clusters(g),
        "favicon": favicon_clusters(ctx),
        "simhash": simhash_clusters(ctx),
        "cohosted_ip": cohosted_ips(g),
        "org_asn": org_asn_assets(g, ctx.scope.keywords()),
    }
