"""Attack-surface drift: compare two rcn-mstr run directories and report what changed.

Continuous recon is where real bugs appear: a new subdomain, a freshly-opened port, a cert that
changed, a service that regressed to 200 from 403. `rcn-mstr diff OLD NEW` emits a structured diff
(and a human summary) so a watcher/AI can act only on the delta.
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Set


def _load_jsonl(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def _load_set(path: str) -> Set[str]:
    if not os.path.exists(path):
        return set()
    return {l.strip() for l in open(path, encoding="utf-8") if l.strip()}


def _index(records: List[dict], key: str) -> Dict[str, dict]:
    return {r[key]: r for r in records if key in r}


def diff_runs(old_dir: str, new_dir: str) -> dict:
    out: Dict[str, object] = {"old": old_dir, "new": new_dir}

    # hosts
    old_hosts = _load_set(os.path.join(old_dir, "hosts.txt"))
    new_hosts = _load_set(os.path.join(new_dir, "hosts.txt"))
    old_live = _load_set(os.path.join(old_dir, "hosts_live.txt"))
    new_live = _load_set(os.path.join(new_dir, "hosts_live.txt"))
    out["hosts"] = {
        "new": sorted(new_hosts - old_hosts),
        "removed": sorted(old_hosts - new_hosts),
        "newly_live": sorted(new_live - old_live),
        "went_dark": sorted(old_live - new_live),
    }

    # ips + ports
    old_ips = _index(_load_jsonl(os.path.join(old_dir, "ips.jsonl")), "ip")
    new_ips = _index(_load_jsonl(os.path.join(new_dir, "ips.jsonl")), "ip")
    port_changes = []
    for ip, nrec in new_ips.items():
        oldp = set((old_ips.get(ip) or {}).get("ports", []))
        newp = set(nrec.get("ports", []))
        if newp - oldp:
            port_changes.append({"ip": ip, "new_ports": sorted(newp - oldp),
                                 "closed_ports": sorted(oldp - newp), "hosts": nrec.get("hosts", [])})
    out["ips"] = {"new": sorted(set(new_ips) - set(old_ips)),
                  "removed": sorted(set(old_ips) - set(new_ips)), "port_changes": port_changes}

    # services (by url): status + title + tech + tls fingerprint changes
    old_svc = _index(_load_jsonl(os.path.join(old_dir, "services.jsonl")), "url")
    new_svc = _index(_load_jsonl(os.path.join(new_dir, "services.jsonl")), "url")
    svc_changes = []
    for url, n in new_svc.items():
        o = old_svc.get(url)
        if not o:
            continue
        ch = {}
        if o.get("status") != n.get("status"):
            ch["status"] = [o.get("status"), n.get("status")]
        ot = {t["name"] for t in o.get("tech", [])}
        nt = {t["name"] for t in n.get("tech", [])}
        if ot != nt:
            ch["tech_added"] = sorted(nt - ot)
            ch["tech_removed"] = sorted(ot - nt)
        ofp = (o.get("tls") or {}).get("fingerprint_sha256")
        nfp = (n.get("tls") or {}).get("fingerprint_sha256")
        if ofp != nfp:
            ch["cert_changed"] = [ofp, nfp]
        if o.get("title") != n.get("title"):
            ch["title"] = [o.get("title"), n.get("title")]
        if ch:
            svc_changes.append({"url": url, "changes": ch})
    out["services"] = {"new": sorted(set(new_svc) - set(old_svc)),
                       "removed": sorted(set(old_svc) - set(new_svc)), "changed": svc_changes}

    # findings (by id)
    old_f = _index(_load_jsonl(os.path.join(old_dir, "findings.jsonl")), "id")
    new_f = _index(_load_jsonl(os.path.join(new_dir, "findings.jsonl")), "id")
    out["findings"] = {
        "new": [{"id": i, "type": new_f[i]["type"], "severity": new_f[i]["severity"],
                 "target": new_f[i]["target"], "title": new_f[i]["title"]}
                for i in sorted(set(new_f) - set(old_f))],
        "resolved": [{"id": i, "type": old_f[i]["type"], "target": old_f[i]["target"],
                      "title": old_f[i]["title"]} for i in sorted(set(old_f) - set(new_f))],
    }

    # hypotheses (by id)
    old_h = _index(_load_jsonl(os.path.join(old_dir, "hypotheses.jsonl")), "id")
    new_h = _index(_load_jsonl(os.path.join(new_dir, "hypotheses.jsonl")), "id")
    out["hypotheses"] = {"new": [new_h[i] for i in sorted(set(new_h) - set(old_h))]}

    # significance score: weight new live hosts, new open ports, new high/critical findings
    sev_w = {"info": 0, "low": 1, "medium": 3, "high": 8, "critical": 13}
    score = (len(out["hosts"]["newly_live"]) * 2 + len(out["ips"]["port_changes"]) * 3 +
             sum(sev_w.get(f["severity"], 1) for f in out["findings"]["new"]) +
             len(out["services"]["new"]))
    out["drift_score"] = score
    out["has_changes"] = bool(
        out["hosts"]["new"] or out["hosts"]["newly_live"] or port_changes or svc_changes or
        out["findings"]["new"] or out["services"]["new"])
    return out


def summarize(d: dict) -> str:
    h, ips, svc, fnd = d["hosts"], d["ips"], d["services"], d["findings"]
    lines = [f"# attack-surface drift (score {d['drift_score']})",
             f"old: {d['old']}", f"new: {d['new']}", ""]
    lines.append(f"hosts: +{len(h['new'])} new, +{len(h['newly_live'])} newly-live, "
                 f"-{len(h['removed'])} gone, {len(h['went_dark'])} went dark")
    for x in h["new"][:30]:
        lines.append(f"  + host {x}")
    for x in h["newly_live"][:30]:
        lines.append(f"  ^ now live {x}")
    lines.append(f"ports: {len(ips['port_changes'])} IPs changed")
    for pc in ips["port_changes"][:20]:
        if pc["new_ports"]:
            lines.append(f"  + {pc['ip']} opened {pc['new_ports']} ({', '.join(pc['hosts'][:3])})")
    lines.append(f"services: +{len(svc['new'])} new, {len(svc['changed'])} changed")
    for sc in svc["changed"][:20]:
        lines.append(f"  ~ {sc['url']}: {sc['changes']}")
    lines.append(f"findings: +{len(fnd['new'])} new, -{len(fnd['resolved'])} resolved")
    for f in sorted(fnd["new"], key=lambda x: x["severity"], reverse=True)[:30]:
        lines.append(f"  + [{f['severity'].upper()}] {f['type']} {f['target']} :: {f['title']}")
    if d["hypotheses"]["new"]:
        lines.append(f"new attack hypotheses: {len(d['hypotheses']['new'])}")
        for hyp in d["hypotheses"]["new"][:10]:
            lines.append(f"  ! [{hyp['severity'].upper()}] {hyp['title']}")
    return "\n".join(lines)
