"""Write all raw outputs to the output directory at the end of a run."""
from __future__ import annotations

import json
import os

from .util import iso


def _sev(s):
    return ["info", "low", "medium", "high", "critical"].index(s)


def _conf(c):
    return ["tentative", "low", "medium", "high", "confirmed"].index(c)


def write_outputs(ctx):
    out = ctx.outdir
    # findings.jsonl (ranked)
    findings = sorted(ctx.findings.values(), key=lambda f: (-_sev(f["severity"]), -_conf(f["confidence"]),
                                                            f["type"]))
    ctx.write_jsonl("findings.jsonl", findings)

    # hosts.jsonl -- one record per host, full dns + http
    host_recs = []
    for h, rec in sorted(ctx.hosts.items()):
        dns = rec.get("dns") or {}
        host_recs.append({
            "host": h, "root": rec.get("root"), "sources": rec.get("sources", []), "tags": rec.get("tags", []),
            "cdn": rec.get("cdn"), "resolved": dns.get("resolved", False), "a": dns.get("a", []),
            "aaaa": dns.get("aaaa", []), "cname": dns.get("cname", []), "rcode": dns.get("rcode"),
            "http": rec.get("http", []), "origin_ips": rec.get("origin_ips", []),
            "first_seen": rec.get("first_seen"), "round": rec.get("round"),
        })
    ctx.write_jsonl("hosts.jsonl", host_recs)
    ctx.write_lines("hosts.txt", sorted(ctx.hosts))
    ctx.write_lines("hosts_live.txt", sorted(ctx.live_hosts()))
    ctx.write_lines("hosts_resolved.txt",
                    sorted(h for h, r in ctx.hosts.items() if (r.get("dns") or {}).get("resolved")))

    # ips.jsonl
    ctx.write_jsonl("ips.jsonl", [ctx.ips[ip] for ip in sorted(ctx.ips)])
    ctx.write_lines("ips.txt", sorted(ctx.ips))

    # services.jsonl + live urls
    svcs = sorted(ctx.services.values(), key=lambda s: s["url"])
    ctx.write_jsonl("services.jsonl", svcs)
    ctx.write_lines("urls_live.txt", [s["url"] for s in svcs if s["status"] < 500])

    # zones + email security
    ctx.write_jsonl("zones.jsonl", [ctx.zones[z] for z in sorted(ctx.zones)])

    if ctx.params:
        ctx.write_lines("params.txt", sorted(ctx.params))
    if ctx.paths:
        ctx.write_lines("paths.txt", sorted(ctx.paths))

    # run metadata + summary
    meta = {
        "tool": "rcn-mstr", "version": "1.0.0", "started": iso(ctx.started), "finished": iso(),
        "duration_sec": round(__import__("time").time() - ctx.started, 1),
        "config": {"roots": ctx.scope.roots, "mode": ctx.cfg.mode, "rounds_run": ctx.round,
                   "max_rounds": ctx.cfg.max_rounds, "brute": ctx.cfg.brute},
        "dns": {"mode": ctx.stats.get("dns_mode"), "health": ctx.stats.get("dns_health"),
                "resolver_stats": ctx.resolver.stats if ctx.resolver else {}},
        "sources": ctx.stats.get("sources", {}),
        "module_status": ctx.module_status,
        "output_files": ctx.out_counts,
        "archive_urls": ctx.stats.get("archive_urls"),
    }
    ctx.write_json("run.json", meta)
    ctx.write_json("summary.json", ctx.stats.get("summary", {}))

    # top-level index for the downstream AI harness
    index = {
        "schema": "rcn-mstr/1.1",
        "summary": ctx.stats.get("summary", {}),
        "graph": ctx.stats.get("graph", {}),
        "hypotheses_count": len(ctx.hypotheses),
        "top_hypotheses": [
            {"id": h["id"], "category": h["category"], "severity": h["severity"],
             "confidence": h["confidence"], "title": h["title"], "targets": h["targets"]}
            for h in ctx.hypotheses[:15]
        ],
        "files": {
            "hypotheses": "hypotheses.jsonl",
            "findings": "findings.jsonl",
            "graph_nodes": "graph_nodes.jsonl",
            "graph_edges": "graph_edges.jsonl",
            "graph_dot": "graph.dot",
            "clusters": "clusters.json",
            "hosts": "hosts.jsonl",
            "hosts_live": "hosts_live.txt",
            "ips": "ips.jsonl",
            "services": "services.jsonl",
            "zones": "zones.jsonl",
            "urls_all": "urls_all.txt",
            "urls_live": "urls_live.txt",
            "params": "params.txt",
            "run": "run.json",
            "events_dir": ".",
        },
        "ingestion_hint": ("Start with hypotheses.jsonl (ranked attack chains, each with an agent_prompt). "
                           "Pivot through graph_nodes.jsonl/graph_edges.jsonl (typed knowledge graph). "
                           "findings.jsonl has the raw evidence; *.jsonl are per-phase event streams."),
        "event_streams": sorted(k for k in ctx.out_counts),
    }
    ctx.write_json("index.json", index)
    _write_readme(ctx)


def _write_readme(ctx):
    s = ctx.stats.get("summary", {})
    c = s.get("counts", {})
    sev = s.get("findings_by_severity", {})
    lines = [
        f"# rcn-mstr recon output: {', '.join(ctx.scope.roots)}",
        "",
        f"- mode: {ctx.cfg.mode}   dns: {ctx.stats.get('dns_mode')}   rounds: {ctx.round}",
        f"- hosts: {c.get('hosts_total', 0)} total / {c.get('hosts_live', 0)} live "
        f"({c.get('hosts_direct', 0)} direct, {c.get('hosts_cdn', 0)} behind CDN)",
        f"- ips: {c.get('ips', 0)}   services: {c.get('services', 0)}   findings: {c.get('findings', 0)}",
        f"- findings by severity: " + ", ".join(f"{k}={v}" for k, v in sev.items()) if sev else "- no findings",
        "",
        f"- attack hypotheses: {len(ctx.hypotheses)}   graph: {ctx.stats.get('graph', {}).get('nodes', 0)} nodes / "
        f"{ctx.stats.get('graph', {}).get('edges', 0)} edges",
        "",
        "## Files",
        "- `index.json` - machine entrypoint (summary + file map). Start here for AI ingestion.",
        "- `hypotheses.jsonl` - **ranked attack chains**, each with rationale, evidence node ids, concrete",
        "  steps and a self-contained `agent_prompt` for an autonomous follow-up agent. Start here.",
        "- `graph_nodes.jsonl` / `graph_edges.jsonl` / `graph.dot` - typed correlation knowledge graph.",
        "- `clusters.json` - cert/favicon/body/co-host/ASN clusters (shared-infra structure).",
        "- `findings.jsonl` - ranked findings (id,type,severity,confidence,target,title,evidence,next_steps).",
        "- `hosts.jsonl` / `hosts_live.txt` - every host with DNS + HTTP context.",
        "- `services.jsonl` - HTTP services (status,title,tech,tls,headers,favicon,cors).",
        "- `ips.jsonl` - IPs with ASN/CDN/PTR/InternetDB/ports.",
        "- `zones.jsonl` - apex records + SPF/DMARC/DKIM analysis.",
        "- `urls_all.txt` / `urls_live.txt` / `params.txt` - archive + crawl surface.",
        "- `*.jsonl` event streams: dns, ip, service, portscan, archive_url, axfr, delegation, github_code, ...",
        "- `run.json` - run metadata, per-source and per-module status.",
        "",
        "Every record is raw JSON intended for a downstream AI agent to triage and attack.",
    ]
    with open(os.path.join(ctx.outdir, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
