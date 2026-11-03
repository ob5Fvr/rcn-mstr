"""Attack-hypothesis engine.

This is what sets rcn-mstr apart: instead of only emitting facts, it reasons over the correlation
graph and the findings to produce ranked, evidence-linked ATTACK HYPOTHESES - testable chains a
human or a downstream AI agent should pursue first. Each hypothesis carries:

  id, title, category, severity, confidence (0-1), rationale, evidence (node ids + raw facts),
  targets, steps (concrete, reproducible), and `agent_prompt` (a self-contained instruction written
  for an autonomous follow-up agent).

Everything is derived deterministically from the graph/ctx, so it is explainable and testable.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from . import graph as G

STAGING_KW = ("staging", "stg", "stage", "dev", "qa", "uat", "test", "preprod", "sandbox", "demo", "internal",
              "beta", "alpha", "canary", "old", "legacy", "temp", "tmp")


def _id(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:12]


class Hypothesis(dict):
    @classmethod
    def make(cls, category, title, severity, confidence, rationale, targets, evidence, steps, agent_prompt,
             refs=()):
        h = cls()
        h.update(id=_id(category, *targets), category=category, title=title, severity=severity,
                 confidence=round(confidence, 2), rationale=rationale, targets=list(targets),
                 evidence=evidence, steps=list(steps), agent_prompt=agent_prompt, references=list(refs))
        return h


def _sev_rank(s):
    return ["info", "low", "medium", "high", "critical"].index(s)


def generate(ctx, g: G.Graph, clusters: dict) -> List[dict]:
    H: List[Hypothesis] = []
    findings = list(ctx.findings.values())
    by_type: Dict[str, list] = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)

    def host_rec(h):
        return ctx.hosts.get(h, {})

    # 1. FORGOTTEN ORIGIN: source/debug leak on a directly-reachable (non-CDN) host
    leak_types = {"content_exposure", "source_map"}
    for f in findings:
        if f["type"] not in leak_types:
            continue
        tags = set(f.get("tags", []))
        if not (tags & {"vcs", "source-leak", "secret", "config", "actuator", "debug"}):
            continue
        host = _finding_host(f)
        rec = host_rec(host)
        direct = rec and not rec.get("cdn")
        if direct:
            H.append(Hypothesis.make(
                "forgotten_origin",
                f"Directly-reachable host leaks source/debug data: {host}",
                "high", 0.8 if f["severity"] in ("high", "critical") else 0.6,
                f"{host} is not behind a CDN and exposes {f['title']}. Direct origin assets with source/"
                f"config leaks are classic high-impact footholds (code, secrets, internal paths).",
                [host], {"finding": f["id"], "fact": f["title"], "ips": rec.get("dns", {}).get("a", [])},
                [f"Fetch {f['target']} directly and review the leaked content",
                 "Pull secrets/paths; map them back to the main application",
                 "If .git: dump the repo with git-dumper and scan history for credentials"],
                f"Investigate {f['target']} on host {host}. It exposes '{f['title']}'. Download the content, "
                f"extract any secrets, source, or internal endpoints, and determine blast radius against the "
                f"primary application."))

    # 2. CDN-BYPASS CHAIN: verified origin IP + a sensitive exposure reachable on it
    for f in by_type.get("origin_ip_exposure", []):
        host = _finding_host(f)
        ip = (f.get("evidence") or {}).get("ip")
        co_findings = [x for x in findings if x["type"] in ("content_exposure", "exposed_service", "secret")
                       and ip and ip in str(x.get("target", ""))]
        conf = 0.85 if co_findings else 0.6
        H.append(Hypothesis.make(
            "cdn_bypass", f"Origin IP {ip} bypasses the CDN/WAF for {host}", "high", conf,
            f"{host} is CDN-fronted ({host_rec(host).get('cdn')}) but {ip} answers directly with a matching "
            f"response. Requests to the origin skip the CDN WAF, rate-limits and bot rules entirely.",
            [host, ip], {"finding": f["id"], "origin_ip": ip, "direct_exposures": [c['id'] for c in co_findings]},
            [f"curl -k -H 'Host: {host}' https://{ip}/ and compare to the fronted response",
             "Replay any WAF-blocked payloads straight to the origin IP",
             "Scan the origin IP for services the CDN hides"],
            f"Host {host} is fronted by a CDN/WAF but origin IP {ip} serves the same site directly. Re-test all "
            f"access-control and injection points against {ip} with Host: {host}, bypassing the edge."))

    # 3. SHADOW STAGING via shared cert cluster on different infra
    for cl in clusters.get("cert", []):
        hosts = cl["hosts"]
        staging = [h for h in hosts if any(k in h for k in STAGING_KW)]
        prod = [h for h in hosts if h not in staging]
        if staging and prod:
            direct_staging = [h for h in staging if host_rec(h) and not host_rec(h).get("cdn")]
            conf = 0.75 if direct_staging else 0.5
            H.append(Hypothesis.make(
                "shadow_staging",
                f"Non-production siblings share a TLS cert with production: {', '.join(staging[:3])}",
                "high" if direct_staging else "medium", conf,
                f"The certificate {cl['cn']} covers both production ({prod[:2]}) and non-production "
                f"({staging[:2]}) names. Staging/dev deployments of the same app often skip auth, run debug "
                f"mode, use weaker creds and expose pre-release endpoints.",
                staging, {"cert": cl["cert"], "production": prod[:5], "staging": staging[:5],
                          "direct": direct_staging},
                ["Browse each non-prod host; compare auth and exposed features vs production",
                 "Look for debug flags, default creds, verbose errors, unfinished endpoints"],
                f"These hosts {staging} share a TLS certificate with production hosts {prod[:3]}, so they run the "
                f"same application in a lower environment. Enumerate them for missing authentication, debug "
                f"endpoints and weaker controls than production."))

    # 4. ACCESS-CONTROL GAP: a 2xx service inside an otherwise-blocked simhash cluster
    for cl in clusters.get("simhash", []):
        statuses = cl["statuses"]
        allowed = [u for u, s in statuses.items() if s and s < 400]
        blocked = [u for u, s in statuses.items() if s in (401, 403)]
        if allowed and blocked and len(blocked) >= len(allowed):
            H.append(Hypothesis.make(
                "access_control_gap",
                f"One instance is open while identical siblings require auth: {allowed[:2]}",
                "high", 0.6,
                f"{len(blocked)} near-identical services return 401/403 but {allowed} return 2xx. Same app, "
                f"inconsistent access control - the open instance likely leaks data the others protect.",
                allowed, {"open": allowed, "blocked": blocked},
                ["Compare the open instance's content against the protected ones",
                 "Enumerate data/functions exposed only on the open node"],
                f"These services are byte-similar yet {blocked[:2]} demand auth while {allowed} are open. Treat "
                f"{allowed} as an authentication-bypass of the same app and extract whatever the others protect."))

    # 5. TAKEOVER-READY
    for f in by_type.get("subdomain_takeover", []) + by_type.get("ns_takeover", []):
        H.append(Hypothesis.make(
            "takeover", f"Subdomain/NS takeover primitive: {f['target']}", f["severity"],
            0.9 if f["confidence"] in ("high", "confirmed") else 0.6,
            f["title"] + ". Claiming the dangling resource yields content control (and often cookie/OAuth "
            "scope) on an in-scope name.",
            [f["target"]], {"finding": f["id"], "evidence": f.get("evidence")},
            f.get("next_steps", ["Claim the dangling resource per the provider's process"]),
            f"Attempt the takeover described by '{f['title']}' for {f['target']}. Register/claim the resource, "
            f"serve a benign proof marker, and document the exact steps."))

    # 6. SECRET -> SERVICE PIVOT: a live credential plus infra it likely unlocks
    secret_findings = by_type.get("secret", [])
    high_secrets = [f for f in secret_findings if f["severity"] == "high"]
    buckets = by_type.get("cloud_bucket", [])
    if high_secrets:
        rules = sorted({f["evidence"]["rule"] for f in high_secrets if f.get("evidence")})
        H.append(Hypothesis.make(
            "secret_pivot", f"Live-looking secrets exposed in client code ({len(high_secrets)})", "high", 0.55,
            f"High-signal secrets ({', '.join(rules[:6])}) were found in JS/HTML. If still valid they unlock "
            f"cloud, source or third-party APIs. Cross-reference with discovered buckets/services for a pivot.",
            [f["target"] for f in high_secrets[:5]],
            {"secrets": [f["id"] for f in high_secrets[:10]], "rules": rules,
             "buckets": [b["target"] for b in buckets[:5]]},
            ["Validate each key out-of-band (read-only call) before use",
             "Map AWS/GCP keys to the exposed buckets and enumerate permissions",
             "Rotate-check: determine if the key is production"],
            "Validate these exposed secrets with minimal read-only calls. For any live cloud key, enumerate its "
            "permissions and tie it to the discovered storage buckets to establish impact."))

    # 7. UNAUTH DATASTORE / RCE SERVICE
    for f in by_type.get("exposed_service", []):
        if f["severity"] in ("high", "critical"):
            H.append(Hypothesis.make(
                "exposed_datastore", f["title"], f["severity"],
                0.8 if f["confidence"] in ("high", "confirmed") else 0.5, f["title"] + ".",
                [f["target"]], {"finding": f["id"], "evidence": f.get("evidence")},
                f.get("next_steps", ["Connect with the native client and test unauthenticated access"]),
                f"A sensitive service is exposed: '{f['title']}' at {f['target']}. Connect with the appropriate "
                f"client and determine whether it is unauthenticated and what data/commands are reachable."))

    # 8. EMAIL SPOOFING (business-impact, often in-scope)
    spoof = [f for f in by_type.get("email_spoofing", []) if "missing" in str(f.get("title", "")).lower()
             or "+all" in str(f.get("title", "")) or "none" in str(f.get("title", "")).lower()]
    for f in spoof[:5]:
        H.append(Hypothesis.make(
            "email_spoofing", f["title"], "medium", 0.6, f["title"] +
            ". Weak SPF/DMARC lets an attacker send mail as the domain (phishing / BEC).",
            [f["target"]], {"finding": f["id"]},
            [f"Send a spoofed test mail as postmaster@{f['target']} to a mailbox you control",
             "Confirm it lands without SPF/DMARC failure"],
            f"Domain {f['target']} has weak email authentication ({f['title']}). Demonstrate a spoofed email "
            f"from the domain to a mailbox you control, respecting program rules."))

    # 9. WAF-BYPASS CONFIRMED
    for f in by_type.get("waf_bypass", []):
        H.append(Hypothesis.make(
            "waf_bypass", f["title"], "high", 0.75, f["title"] +
            ". The edge control is evadable, so protected functionality is reachable.",
            [f["target"]], {"finding": f["id"], "evidence": f.get("evidence")},
            ["Reproduce the winning request manually", "Pivot to the now-reachable functionality / data"],
            f"A WAF/access-control bypass works on {f['target']} ({f['title']}). Reproduce it, then enumerate "
            f"the protected content it exposes."))

    # 10. HIGH-VALUE PARAM SURFACE on a no-WAF live host
    param_findings = by_type.get("archive_params", [])
    cats = {f["evidence"]["category"] for f in param_findings if f.get("evidence")}
    dangerous = cats & {"ssrf", "rce", "sqli", "lfi", "redirect"}
    if dangerous:
        H.append(Hypothesis.make(
            "injection_surface", f"Archived parameters hint at injection surface: {', '.join(sorted(dangerous))}",
            "medium", 0.4,
            f"Historic URLs expose parameters associated with {sorted(dangerous)}. These are untested leads, "
            f"best fed to a fuzzer/active scanner.",
            list(ctx.scope.roots),
            {"categories": sorted(dangerous), "params_file": "params.txt", "urls_file": "urls_all.txt"},
            ["Replay the parameterised URLs against live hosts",
             "Fuzz each class with the matching payload set (gf/nuclei/sqlmap)"],
            "Historic URLs expose parameters classed as " + ", ".join(sorted(dangerous)) +
            ". Replay the live ones and fuzz each parameter class with the appropriate payloads."))

    # 11. SENSITIVE PRODUCT IDENTIFIED (by favicon/tech) -> default-cred / unauth check
    SENSITIVE = {"jenkins", "gitlab", "grafana", "kibana", "phpmyadmin", "rabbitmq", "harbor", "rancher",
                 "kubernetes dashboard", "sonarqube", "nexus", "jupyter", "keycloak", "zabbix", "gitea",
                 "argocd", "consul", "vault", "spring boot actuator"}
    for f in by_type.get("tech_identified", []) + [x for x in findings if x["type"] == "admin_panel"]:
        prod = (f.get("evidence") or {}).get("product", "") or f.get("title", "")
        low = prod.lower()
        if any(s in low for s in SENSITIVE):
            H.append(Hypothesis.make(
                "sensitive_product", f"Sensitive product exposed: {prod} at {f['target']}", "medium", 0.5,
                f"{prod} was identified at {f['target']}. These admin/CI/observability products are frequent "
                f"sources of unauthenticated access, default credentials and known RCE chains.",
                [f["target"]], {"finding": f["id"], "product": prod},
                ["Check for unauthenticated access to privileged functions",
                 "Test default/weak credentials where applicable",
                 "Map the exact version to known CVEs"],
                f"{prod} is reachable at {f['target']}. Determine the version, test for unauthenticated access "
                f"and default credentials, and check it against known CVEs for that product."))

    # dedupe by id (same category+targets), keeping the highest-confidence instance and merging evidence
    best: Dict[str, Hypothesis] = {}
    for h in H:
        cur = best.get(h["id"])
        if cur is None or h["confidence"] > cur["confidence"] or \
                _sev_rank(h["severity"]) > _sev_rank(cur["severity"]):
            if cur and isinstance(cur.get("evidence"), dict) and isinstance(h.get("evidence"), dict):
                h["evidence"].setdefault("related", []).extend(
                    [v for v in cur["evidence"].values() if isinstance(v, str)][:3])
            best[h["id"]] = h
    out = list(best.values())
    # rank: severity desc, then confidence desc
    out.sort(key=lambda h: (-_sev_rank(h["severity"]), -h["confidence"]))
    return out


def _finding_host(f) -> Optional[str]:
    t = f.get("target", "")
    if "://" in t:
        return t.split("://", 1)[1].split("/")[0].split(":")[0]
    return t.split("/")[0].split(":")[0]
