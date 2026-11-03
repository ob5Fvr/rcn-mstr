"""Shared run state + output writers."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .scope import Scope, clean_host
from .util import iso, now

log = logging.getLogger("rcnmstr")

MODES = {"passive": 0, "normal": 1, "deep": 2}
SEVERITIES = ["info", "low", "medium", "high", "critical"]
CONFIDENCE = ["tentative", "low", "medium", "high", "confirmed"]


@dataclass
class Config:
    domains: List[str]
    output: str = "rcn-out"
    mode: str = "normal"
    modules: Optional[List[str]] = None
    skip: List[str] = field(default_factory=list)
    resolvers: Optional[List[str]] = None
    health_name: str = "google.com"
    force_doh: bool = False
    wordlist: Optional[str] = None
    brute: bool = True
    max_rounds: int = 4
    concurrency: int = 80
    dns_concurrency: int = 400
    timeout: float = 10.0
    proxy: Optional[str] = None
    keys: Dict[str, str] = field(default_factory=dict)
    max_permutations: int = 20000
    http_ports: List[int] = field(default_factory=lambda: [80, 443])
    top_ports: int = 100
    scan_ports: Optional[List[int]] = None
    max_js: int = 400
    crawl_depth: int = 1
    max_crawl_pages: int = 6
    archive_limit: int = 50000
    recheck_archive: bool = True
    max_buckets: int = 600
    module_timeout: float = 1800.0
    scope_file: Optional[str] = None
    exclude_file: Optional[str] = None
    allow_private: bool = False  # probe/scan RFC1918 IPs (useful for internal recon / tests)
    user_agent: Optional[str] = None
    tools: bool = True  # use external binaries (subfinder/amass) when on PATH


class Context:
    def __init__(self, cfg: Config, scope: Scope, outdir: str):
        self.cfg = cfg
        self.scope = scope
        self.outdir = outdir
        os.makedirs(outdir, exist_ok=True)
        self.resolver = None
        self.probe = None   # aiohttp session for target traffic
        self.api = None     # aiohttp session for third-party APIs
        self.round = 0
        self.started = now()
        self.hosts: Dict[str, dict] = {}
        self.ips: Dict[str, dict] = {}
        self.services: Dict[str, dict] = {}   # base url -> service record
        self.findings: Dict[str, dict] = {}
        self.urls: Dict[str, dict] = {}
        self.pending_hosts: Set[str] = set()
        self.web_targets: Set[tuple] = set()   # (host_or_ip, port, scheme) extra probe targets
        self.wildcards: Dict[str, dict] = {}   # zone -> {"ips": set, "cnames": set}
        self.zones: Dict[str, dict] = {}       # apex/zone -> records
        self.cloud_refs: Set[str] = set()      # bucket-like references found anywhere
        self.paths: Set[str] = set()           # paths learnt (robots/sitemap/js/archive) for wordlists
        self.params: Set[str] = set()
        self.emails: Set[str] = set()
        self.stats: Dict[str, Any] = {}
        self.module_status: Dict[str, dict] = {}
        self.out_counts: Dict[str, int] = {}
        self._files: Dict[str, Any] = {}
        self.lock = asyncio.Lock()

    # -------------------------------------------------------------- modes / keys
    def mode_allows(self, mode: str) -> bool:
        return MODES[self.cfg.mode] >= MODES[mode]

    def key(self, name: str) -> Optional[str]:
        return self.cfg.keys.get(name) or os.environ.get(name.upper()) or None

    # -------------------------------------------------------------- hosts
    def add_host(self, name: str, source: str) -> bool:
        h = clean_host(name) if name else None
        if not h or not self.scope.in_scope(h):
            return False
        rec = self.hosts.get(h)
        if rec is None:
            self.hosts[h] = {"host": h, "root": self.scope.root_of(h), "sources": [source], "round": self.round,
                             "first_seen": iso(), "dns": None, "tags": []}
            self.pending_hosts.add(h)
            return True
        if source not in rec["sources"]:
            rec["sources"].append(source)
        return False

    def add_hosts(self, names, source: str) -> int:
        return sum(1 for n in names if self.add_host(n, source))

    def tag_host(self, h: str, tag: str):
        rec = self.hosts.get(h)
        if rec is not None and tag not in rec["tags"]:
            rec["tags"].append(tag)

    def web_targets_pending(self) -> bool:
        probed = getattr(self, "_probed_targets", set())
        return bool(self.web_targets - probed)

    def live_hosts(self) -> List[str]:
        return [h for h, r in self.hosts.items() if r.get("dns") and r["dns"].get("resolved")
                and "wildcard" not in r["tags"]]

    def ip_rec(self, ip: str) -> dict:
        rec = self.ips.get(ip)
        if rec is None:
            rec = self.ips[ip] = {"ip": ip, "hosts": [], "asn": None, "prefix": None, "as_name": None,
                                  "country": None, "cdn": None, "ptr": [], "internetdb": None, "ports": []}
        return rec

    # -------------------------------------------------------------- output
    def emit(self, kind: str, obj: dict):
        f = self._files.get(kind)
        if f is None:
            f = self._files[kind] = open(os.path.join(self.outdir, f"{kind}.jsonl"), "a", encoding="utf-8")
        obj.setdefault("ts", iso())
        f.write(json.dumps(obj, default=_default, ensure_ascii=False) + "\n")
        self.out_counts[kind] = self.out_counts.get(kind, 0) + 1

    def finding(self, type: str, severity: str, confidence: str, target: str, title: str, evidence: Any = None,
                module: str = "", tags=(), references=(), next_steps=(), dedupe_key: Optional[str] = None) -> dict:
        assert severity in SEVERITIES, severity
        assert confidence in CONFIDENCE, confidence
        fid = hashlib.sha1(f"{type}|{target}|{dedupe_key or title}".encode()).hexdigest()[:16]
        f = self.findings.get(fid)
        if f:
            if SEVERITIES.index(severity) > SEVERITIES.index(f["severity"]):
                f["severity"] = severity
            if CONFIDENCE.index(confidence) > CONFIDENCE.index(f["confidence"]):
                f["confidence"] = confidence
            return f
        f = {"id": fid, "type": type, "severity": severity, "confidence": confidence, "target": target,
             "title": title, "evidence": evidence, "module": module, "tags": list(tags),
             "references": list(references), "next_steps": list(next_steps), "round": self.round, "ts": iso()}
        self.findings[fid] = f
        log.info("[finding] %-8s %-9s %s :: %s", severity.upper(), confidence, target, title)
        return f

    def write_json(self, name: str, obj):
        with open(os.path.join(self.outdir, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, default=_default, indent=1, ensure_ascii=False)

    def write_lines(self, name: str, lines):
        with open(os.path.join(self.outdir, name), "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(f"{line}\n")

    def write_jsonl(self, name: str, objs):
        with open(os.path.join(self.outdir, name), "w", encoding="utf-8") as fh:
            for o in objs:
                fh.write(json.dumps(o, default=_default, ensure_ascii=False) + "\n")

    def close(self):
        for f in self._files.values():
            f.close()
        self._files.clear()


def _default(o):
    if isinstance(o, set):
        return sorted(o)
    if isinstance(o, bytes):
        return o.decode("latin-1")
    return str(o)
