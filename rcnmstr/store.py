"""ReconStore: load a finished run and query it — the programmatic surface for an AI harness.

    from rcnmstr.store import ReconStore
    s = ReconStore.load("rcn-out/example-...")
    s.hypotheses()                      # ranked attack chains
    s.findings(severity="high")         # filter findings
    s.host("api.example.com")           # full host record
    s.neighbors("host:api.example.com") # graph traversal
    s.subgraph_for_finding(fid)         # evidence subgraph
    s.query("select hosts where cdn is null and resolved")   # tiny query DSL

Pure stdlib; deterministic; unit-tested.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional


def _jsonl(path):
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


class ReconStore:
    def __init__(self, outdir: str):
        self.dir = outdir
        self.index = self._json("index.json")
        self._findings = _jsonl(os.path.join(outdir, "findings.jsonl"))
        self._hypotheses = _jsonl(os.path.join(outdir, "hypotheses.jsonl"))
        self._priority = _jsonl(os.path.join(outdir, "priority_targets.jsonl"))
        self._hosts = _jsonl(os.path.join(outdir, "hosts.jsonl"))
        self._ips = _jsonl(os.path.join(outdir, "ips.jsonl"))
        self._services = _jsonl(os.path.join(outdir, "services.jsonl"))
        self._nodes = {n["id"]: n for n in _jsonl(os.path.join(outdir, "graph_nodes.jsonl"))}
        self._edges = _jsonl(os.path.join(outdir, "graph_edges.jsonl"))
        self._host_idx = {h["host"]: h for h in self._hosts}
        self._ip_idx = {i["ip"]: i for i in self._ips}
        self._finding_idx = {f["id"]: f for f in self._findings}
        self._out = {}
        self._in = {}
        for e in self._edges:
            self._out.setdefault(e["src"], []).append(e)
            self._in.setdefault(e["dst"], []).append(e)

    @classmethod
    def load(cls, outdir: str) -> "ReconStore":
        if not os.path.isdir(outdir):
            raise FileNotFoundError(outdir)
        return cls(outdir)

    def _json(self, name, default=None):
        p = os.path.join(self.dir, name)
        return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else (default or {})

    # ------------------------------------------------------------- summaries
    @property
    def summary(self) -> dict:
        return self.index.get("summary", {})

    def counts(self) -> dict:
        return self.summary.get("counts", {})

    # ------------------------------------------------------------- findings
    def findings(self, severity: Optional[str] = None, type: Optional[str] = None,
                 min_severity: Optional[str] = None, tag: Optional[str] = None) -> List[dict]:
        order = ["info", "low", "medium", "high", "critical"]
        out = self._findings
        if severity:
            out = [f for f in out if f["severity"] == severity]
        if min_severity:
            mi = order.index(min_severity)
            out = [f for f in out if order.index(f["severity"]) >= mi]
        if type:
            out = [f for f in out if f["type"] == type]
        if tag:
            out = [f for f in out if tag in f.get("tags", [])]
        return out

    def finding(self, fid: str) -> Optional[dict]:
        return self._finding_idx.get(fid)

    # ------------------------------------------------------------- hypotheses
    def hypotheses(self, category: Optional[str] = None, min_confidence: float = 0.0) -> List[dict]:
        out = [h for h in self._hypotheses if h.get("confidence", 0) >= min_confidence]
        if category:
            out = [h for h in out if h.get("category") == category]
        return out

    def priority_targets(self, top: int = 20):
        return self._priority[:top]

    def agent_plan(self, top: int = 10) -> List[dict]:
        """The ranked to-do list for an autonomous agent: title + prompt + targets."""
        return [{"id": h["id"], "severity": h["severity"], "confidence": h["confidence"],
                 "title": h["title"], "targets": h["targets"], "agent_prompt": h["agent_prompt"]}
                for h in self._hypotheses[:top]]

    # ------------------------------------------------------------- entities
    def hosts(self, live: Optional[bool] = None, cdn: Optional[bool] = None,
              resolved: Optional[bool] = None) -> List[dict]:
        out = self._hosts
        if resolved is not None:
            out = [h for h in out if bool(h.get("resolved")) == resolved]
        if live is not None:
            out = [h for h in out if bool(h.get("http")) == live]
        if cdn is not None:
            out = [h for h in out if bool(h.get("cdn")) == cdn]
        return out

    def host(self, name: str) -> Optional[dict]:
        return self._host_idx.get(name)

    def ip(self, addr: str) -> Optional[dict]:
        return self._ip_idx.get(addr)

    def services(self, status: Optional[int] = None) -> List[dict]:
        return [s for s in self._services if status is None or s.get("status") == status]

    # ------------------------------------------------------------- graph
    def node(self, nid: str) -> Optional[dict]:
        return self._nodes.get(nid)

    def neighbors(self, nid: str, etype: Optional[str] = None, direction: str = "out") -> List[dict]:
        edges = (self._out.get(nid, []) if direction == "out" else self._in.get(nid, []))
        key = "dst" if direction == "out" else "src"
        return [self._nodes.get(e[key], {"id": e[key]}) for e in edges
                if etype is None or e["type"] == etype]

    def subgraph_for_finding(self, fid: str, depth: int = 1) -> dict:
        """Return the finding's node + everything it touches, out to `depth` hops."""
        start = f"finding:{fid}"
        if start not in self._nodes:
            return {"nodes": [], "edges": []}
        seen = {start}
        frontier = [start]
        edges = []
        for _ in range(depth):
            nxt = []
            for n in frontier:
                for e in self._out.get(n, []) + self._in.get(n, []):
                    edges.append(e)
                    for side in (e["src"], e["dst"]):
                        if side not in seen:
                            seen.add(side)
                            nxt.append(side)
            frontier = nxt
        return {"nodes": [self._nodes[n] for n in seen if n in self._nodes],
                "edges": [dict(t) for t in {tuple(sorted(e.items())) for e in edges}]}

    # ------------------------------------------------------------- tiny query DSL
    def query(self, q: str) -> List[dict]:
        """`select <hosts|ips|services|findings|hypotheses> [where <cond> and ...]`.

        Conditions: `<field> is null|not null|<value>`, `<field> >= <n>`, `<field> contains <s>`.
        """
        parts = q.strip().split(None, 2)
        if not parts or parts[0] != "select":
            raise ValueError("query must start with 'select'")
        coll = parts[1]
        rows = {"hosts": self._hosts, "ips": self._ips, "services": self._services,
                "findings": self._findings, "hypotheses": self._hypotheses}.get(coll)
        if rows is None:
            raise ValueError(f"unknown collection {coll}")
        if len(parts) < 3:
            return list(rows)
        cond = parts[2]
        if cond.startswith("where "):
            cond = cond[6:]
        for clause in [c.strip() for c in cond.split(" and ")]:
            rows = [r for r in rows if _match(r, clause)]
        return rows


def _match(row: dict, clause: str) -> bool:
    toks = clause.split(None, 2)
    if len(toks) < 2:
        return True
    field, op = toks[0], toks[1]
    val = row.get(field)
    if op == "is" and len(toks) == 3:
        rhs = toks[2]
        if rhs == "null":
            return val in (None, "", [], {})
        if rhs == "not null":
            return val not in (None, "", [], {})
        return str(val) == rhs
    if op in (">=", ">", "<=", "<") and len(toks) == 3:
        try:
            a, b = float(val), float(toks[2])
        except (TypeError, ValueError):
            return False
        return {">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b}[op]
    if op == "contains" and len(toks) == 3:
        return toks[2].lower() in str(val).lower()
    if op == "=" and len(toks) == 3:
        return str(val) == toks[2]
    return True
