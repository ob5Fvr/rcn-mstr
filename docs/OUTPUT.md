# Output schema (rcn-mstr/1.1)

All files are in the run output directory. Records are newline-delimited JSON unless noted.
A downstream consumer should read `index.json` first.

## index.json
```jsonc
{
  "schema": "rcn-mstr/1.1",
  "summary": { "roots": [...], "mode": "...", "counts": {...},
               "findings_by_severity": {...}, "findings_by_type": {...},
               "top_technologies": {...}, "asns": {...}, "open_ports": {...},
               "priority_findings": [...] },
  "graph": { "nodes": N, "edges": M, "node_types": {...}, "edge_types": {...} },
  "hypotheses_count": N,
  "top_hypotheses": [ {id, category, severity, confidence, title, targets} ],
  "files": { "hypotheses": "hypotheses.jsonl", ... },
  "ingestion_hint": "Start with hypotheses.jsonl ...",
  "event_streams": [ ... ]
}
```

## priority_targets.jsonl  (ranked triage list)
```jsonc
{ "host": "...", "score": <int>, "cdn": "...|null", "waf": "...|null",
  "reasons": ["direct-origin (no CDN)", "keyword:admin", "open-ports:[6379]", "known-cves", "N findings"],
  "top_findings": ["<finding id>", ...] }
```
Higher score = more attack-worthy. Derived from direct-origin, sensitive open ports, known CVEs,
finding severities and juicy hostname keywords.

## hypotheses.jsonl  (ranked; read first)
```jsonc
{ "id": "…", "category": "forgotten_origin|cdn_bypass|shadow_staging|access_control_gap|takeover|
             secret_pivot|exposed_datastore|email_spoofing|waf_bypass|injection_surface",
  "title": "…", "severity": "info|low|medium|high|critical", "confidence": 0.0-1.0,
  "rationale": "why this is a lead",
  "targets": ["host/ip/url"],
  "evidence": { "finding": "<finding id>", ... raw facts, graph node refs ... },
  "steps": ["concrete reproduction steps"],
  "agent_prompt": "self-contained instruction for an autonomous follow-up agent",
  "references": [...] }
```

## findings.jsonl
```jsonc
{ "id": "16-hex", "type": "...", "severity": "...", "confidence": "...",
  "target": "host|ip|url", "title": "...", "evidence": {...},
  "module": "...", "tags": [...], "references": [...], "next_steps": [...],
  "round": N, "ts": "ISO8601" }
```
Finding `type`s include: `subdomain_takeover`, `ns_takeover`, `dangling_dns`, `email_spoofing`,
`dns_zone_transfer`, `cors_misconfig`, `content_exposure`, `secret`, `source_map`, `info_leak`,
`exposed_service`, `known_vulns`, `origin_ip_exposure`, `cloud_bucket`, `tls_issue`,
`access_control`, `admin_panel`, `waf`, `waf_bypass`, `archive_params`, `archive_live_file`,
`asset_cluster`, `interesting_host`, `asn_ownership`.

## graph_nodes.jsonl / graph_edges.jsonl
```jsonc
// node
{ "id": "host:www.example.com", "type": "host|ip|asn|cert|favicon|tech|service|finding|netblock|cname_target",
  "label": "...", ...type-specific attrs... }
// edge
{ "src": "<node id>", "dst": "<node id>",
  "type": "resolves_to|in_asn|in_netblock|presents_cert|covers|has_favicon|runs|serves|cname|about",
  ...attrs... }
```

## clusters.json
```jsonc
{ "cert": [{cert, cn, hosts, sans}],
  "favicon": [{favicon_mmh3, services}],
  "simhash": [{size, services, statuses, distinct_statuses}],
  "cohosted_ip": [{ip, hosts, asn, as_name}],
  "org_asn": [{asn, as_name, ips, hosts}] }
```

## hosts.jsonl
```jsonc
{ "host": "...", "root": "...", "sources": [...], "tags": [...], "cdn": "...|null",
  "resolved": bool, "a": [...], "aaaa": [...], "cname": [...], "rcode": "...",
  "http": [{url,status,title,tech}], "origin_ips": [...], "first_seen": "...", "round": N }
```

## ips.jsonl
```jsonc
{ "ip": "...", "hosts": [...], "asn": "...", "prefix": "...", "as_name": "...",
  "country": "...", "cdn": "...|null", "cdn_range": "...", "ptr": [...],
  "internetdb": {ports,cpes,vulns,hostnames,tags}, "ports": [...], "banners": {port: "..."} }
```

## services.jsonl
```jsonc
{ "url": "...", "host": "...", "scheme": "...", "port": N, "status": N, "title": "...",
  "server": "...", "content_type": "...", "content_length": N, "body_sha1": "...", "simhash": N,
  "tech": [{name,category,via,cpe}], "redirects": [...], "location": "...",
  "security_headers": {...}, "missing_security_headers": [...], "cookies": [{name,secure,httponly,samesite}],
  "csp_hosts": [...], "tls": {subject,issuer,sans,serial,fingerprint_sha256,not_before,not_after,
                              self_signed,common_name,issuer_cn,tls_version,days_to_expiry},
  "favicon_mmh3": N, "favicon_sha1": "...", "waf": [{vendor,via,confidence}],
  "content": [{path,status,length,content_type,severity}] }
```

## zones.jsonl
```jsonc
{ "zone": "...", "A/AAAA/MX/NS/TXT/SOA/CAA/SRV": [...], "saas_verification": [...],
  "ns_ips": [[ns,ip]],
  "email": { "spf": {records,all,includes,ip4,ip6,lookups,total_lookups,issues},
             "dmarc": {records,tags,issues},
             "dkim": {selector: {record,key_b64_len,weak,revoked}} } }
```

## Plain-text helpers
`hosts.txt`, `hosts_live.txt`, `hosts_resolved.txt`, `ips.txt`, `urls_all.txt`, `urls_live.txt`,
`params.txt`, `paths.txt` — one entry per line, for piping into other tools.
