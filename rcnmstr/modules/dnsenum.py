"""DNS: resolution, wildcard detection, zone records, AXFR, email security, brute force, permutations."""
from __future__ import annotations

import asyncio
import os
import re
from typing import Dict, List, Optional, Set

from ..base import Module, gather_limited
from ..dns.resolver import random_label
from ..scope import clean_host, registrable
from ..util import is_public_ip

DATA = os.path.join(os.path.dirname(__file__), "..", "data")


# ----------------------------------------------------------------------------- wildcard helpers


async def wildcard_signature(ctx, zone: str) -> Optional[dict]:
    """Return {'ips': set, 'cnames': set} if *.zone resolves, else None. Cached per zone.

    Concurrency-safe: the first caller computes the signature while others await the same future,
    so a parallel caller never sees a half-built placeholder and wrongly skips wildcard filtering.
    """
    if zone in ctx.wildcards:
        return ctx.wildcards[zone] or None
    inflight = ctx.__dict__.setdefault("_wildcard_inflight", {})
    fut = inflight.get(zone)
    if fut is not None:
        return await asyncio.shield(fut)
    fut = asyncio.get_running_loop().create_future()
    inflight[zone] = fut
    try:
        res = await asyncio.gather(*(ctx.resolver.resolve_host(f"{random_label()}.{zone}") for _ in range(3)))
        hits = [r for r in res if r["resolved"] or (r["cname"] and r["rcode"] == "NOERROR")]
        if not hits:
            ctx.wildcards[zone] = {}
            fut.set_result(None)
            return None
        sig = {"ips": set(), "cnames": set(), "zone": zone}
        for r in hits:
            sig["ips"].update(r["a"] + r["aaaa"])
            sig["cnames"].update(r["cname"])
        ctx.wildcards[zone] = sig
        ctx.emit("wildcards", {"zone": zone, "ips": sorted(sig["ips"]), "cnames": sorted(sig["cnames"])})
        fut.set_result(sig)
        return sig
    except BaseException as e:
        if not fut.done():
            fut.set_exception(e)
            fut.exception()
        ctx.wildcards.pop(zone, None)
        raise
    finally:
        inflight.pop(zone, None)


def matches_wildcard(info: dict, sig: Optional[dict]) -> bool:
    if not sig:
        return False
    ips = set(info.get("a", []) + info.get("aaaa", []))
    if ips and ips <= sig["ips"]:
        return True
    if info.get("cname") and set(info["cname"]) & sig["cnames"]:
        return True
    return False


def parent_zone(host: str) -> Optional[str]:
    return host.split(".", 1)[1] if "." in host else None


async def is_wildcard_hit(ctx, host: str, info: dict) -> bool:
    parent = parent_zone(host)
    if not parent or not ctx.scope.in_scope(parent):
        return False
    return matches_wildcard(info, await wildcard_signature(ctx, parent))


def record_resolution(ctx, host: str, info: dict):
    rec = ctx.hosts.get(host)
    if rec is None:
        return
    rec["dns"] = info
    for ip in info["a"] + info["aaaa"]:
        ip_rec = ctx.ip_rec(ip)
        if host not in ip_rec["hosts"]:
            ip_rec["hosts"].append(host)
    # CNAME targets inside scope are hosts too
    for c in info["cname"]:
        if ctx.scope.in_scope(c):
            ctx.add_host(c, "cname")


class DNSResolve(Module):
    name = "resolve"
    phase = 20
    mode = "passive"
    loop = True
    description = "Resolve every discovered host (A/AAAA/CNAME chain), tag wildcard matches"

    async def run(self, ctx):
        while ctx.pending_hosts:
            batch = list(ctx.pending_hosts)
            ctx.pending_hosts.clear()
            results = await gather_limited([ctx.resolver.resolve_host(h) for h in batch], ctx.cfg.dns_concurrency)
            for h, info in zip(batch, results):
                if isinstance(info, Exception):
                    continue
                record_resolution(ctx, h, info)
                if info["resolved"] and await is_wildcard_hit(ctx, h, info):
                    srcs = ctx.hosts[h]["sources"]
                    if not set(srcs) & {"input", "crtsh", "certspotter", "tls"}:
                        ctx.tag_host(h, "wildcard")
                ctx.emit("dns", info)
        live = len(ctx.live_hosts())
        self.log.info("resolved: %d hosts known, %d live", len(ctx.hosts), live)


# ----------------------------------------------------------------------------- zone records + email security

DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim",
                  "smtp", "mandrill", "mxvault", "everlytickey1", "everlytickey2", "zoho", "zmail", "mailjet",
                  "protonmail", "protonmail2", "protonmail3", "pm", "sendgrid", "smtpapi", "amazonses", "ses",
                  "cm", "m1", "mta", "key1", "key2", "sig1", "fm1", "fm2", "fm3", "mailchimp", "mc", "hs1", "hs2",
                  "turbo-smtp", "sparkpost", "scph0920", "dk", "200608", "20161025", "20210112", "postmark", "pf2014"]

VERIFICATION_PATTERNS = {
    r"^google-site-verification=": "Google Workspace/Search Console", r"^MS=": "Microsoft 365",
    r"^atlassian-domain-verification=": "Atlassian", r"^facebook-domain-verification=": "Facebook/Meta",
    r"^apple-domain-verification=": "Apple", r"^docusign=": "DocuSign", r"^adobe-idp-site-verification=": "Adobe",
    r"^stripe-verification=": "Stripe", r"^zoom-verification": "Zoom", r"^slack-domain-verification": "Slack",
    r"^miro-verification": "Miro", r"^hubspot-developer-verification": "HubSpot", r"^_?globalsign": "GlobalSign",
    r"^dropbox-domain-verification": "Dropbox", r"^onetrust-domain-verification": "OneTrust",
    r"^cisco-ci-domain-verification": "Cisco Webex", r"^box-domain-verification": "Box",
    r"^amazonses": "Amazon SES", r"^mailru-verification": "Mail.ru", r"^yandex-verification": "Yandex",
    r"^teamviewer-sso-verification": "TeamViewer", r"^logmein-verification": "LogMeIn",
    r"^citrix-verification-code": "Citrix", r"^knowbe4-site-verification": "KnowBe4",
    r"^status-page-domain-verification": "Statuspage", r"^twilio-domain-verification": "Twilio",
    r"^openai-domain-verification": "OpenAI", r"^canva-site-verification": "Canva",
    r"^notion-domain-verification": "Notion", r"^github-verification": "GitHub", r"^gitlab": "GitLab",
    r"^okta-verification": "Okta", r"^pardot": "Salesforce Pardot", r"^salesforce": "Salesforce",
    r"^zendesk": "Zendesk", r"^sendinblue": "Brevo", r"^mandrill": "Mailchimp/Mandrill",
    r"^heroku-domain-verification": "Heroku", r"^wiz-domain-verification": "Wiz",
    r"^segment-site-verification": "Segment", r"^webexdomainverification": "Webex",
    r"^1password-site-verification": "1Password", r"^asv=": "Microsoft (ASV)",
}

SPF_LOOKUP_MECHS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def analyze_spf(txts: List[str]) -> dict:
    spfs = [t for t in txts if t.lower().startswith("v=spf1")]
    res = {"records": spfs, "all": None, "includes": [], "ip4": [], "ip6": [], "lookups": 0, "issues": []}
    if not spfs:
        res["issues"].append("missing")
        return res
    if len(spfs) > 1:
        res["issues"].append("multiple_spf_records")
    for term in spfs[0].split()[1:]:
        t = term.lower()
        q = t[0] if t[0] in "+-~?" else "+"
        body = t[1:] if t[0] in "+-~?" else t
        if body == "all":
            res["all"] = q + "all"
        elif body.startswith("include:"):
            res["includes"].append(body[8:])
            res["lookups"] += 1
        elif body.startswith("ip4:"):
            res["ip4"].append(body[4:])
        elif body.startswith("ip6:"):
            res["ip6"].append(body[4:])
        elif body.startswith("redirect="):
            res["redirect"] = body[9:]
            res["lookups"] += 1
        elif body.split(":")[0].split("/")[0] in ("a", "mx", "ptr", "exists"):
            res["lookups"] += 1
    if res["all"] == "+all":
        res["issues"].append("pass_all")
    elif res["all"] == "?all":
        res["issues"].append("neutral_all")
    elif res["all"] == "~all":
        res["issues"].append("softfail_all")
    elif res["all"] is None and "redirect" not in res:
        res["issues"].append("no_all_mechanism")
    return res


def analyze_dmarc(txts: List[str]) -> dict:
    recs = [t for t in txts if t.lower().replace(" ", "").startswith("v=dmarc1")]
    res = {"records": recs, "tags": {}, "issues": []}
    if not recs:
        res["issues"].append("missing")
        return res
    for part in recs[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            res["tags"][k.strip().lower()] = v.strip()
    p = res["tags"].get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        res["issues"].append("invalid_policy")
    elif p == "none":
        res["issues"].append("policy_none")
    sp = res["tags"].get("sp", "").lower()
    if sp == "none" and p != "none":
        res["issues"].append("subdomain_policy_none")
    try:
        if int(res["tags"].get("pct", "100")) < 100:
            res["issues"].append("pct_below_100")
    except ValueError:
        pass
    if "rua" not in res["tags"]:
        res["issues"].append("no_aggregate_reporting")
    return res


class DNSRecords(Module):
    name = "dnsrecords"
    phase = 22
    mode = "passive"
    loop = True
    description = "Apex record sets (MX/NS/TXT/SOA/CAA/SRV), SaaS verification tokens, SPF/DMARC/DKIM, AXFR"

    async def run(self, ctx):
        zones = [z for z in ctx.scope.roots if z not in self.done]
        # sub-zones with their own NS delegation discovered by other modules
        zones += [z for z in ctx.zones if z not in self.done and z not in zones]
        await asyncio.gather(*(self._zone(ctx, z) for z in zones))

    async def _zone(self, ctx, zone):
        self.done.add(zone)
        r = ctx.resolver
        qtypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]
        ans = await asyncio.gather(*(r.query(zone, t) for t in qtypes))
        rec = ctx.zones.setdefault(zone, {})
        rec.update({"zone": zone, "rcode": ans[0].rcode})
        for t, a in zip(qtypes, ans):
            rec[t] = a.values(t)
        if not rec.get("SOA") and not rec.get("NS"):
            rec["note"] = "no SOA/NS at this name (not a zone apex)"
        srv_names = ["_sip._tls", "_sipfederationtls._tcp", "_autodiscover._tcp", "_xmpp-server._tcp",
                     "_ldap._tcp", "_kerberos._tcp", "_caldavs._tcp", "_imaps._tcp", "_submission._tcp",
                     "_minecraft._tcp", "_jabber._tcp", "_gc._tcp"]
        srv = await asyncio.gather(*(r.query(f"{s}.{zone}", "SRV") for s in srv_names))
        rec["SRV"] = {s: a.values("SRV") for s, a in zip(srv_names, srv) if a.values("SRV")}
        for s in rec["SRV"].values():
            for x in s:
                ctx.add_host(x["target"], "srv")
        for mx in rec["MX"]:
            ctx.add_host(mx["exchange"], "mx")
        for ns in rec["NS"]:
            ctx.add_host(ns, "ns")
        # SaaS fingerprints from TXT
        saas = set()
        for t in rec["TXT"]:
            for pat, svc in VERIFICATION_PATTERNS.items():
                if re.search(pat, t, re.I):
                    saas.add(svc)
        rec["saas_verification"] = sorted(saas)
        await self._email(ctx, zone, rec)
        await self._axfr(ctx, zone, rec)
        await self._nsec_walk(ctx, zone, rec)
        ctx.emit("zones", rec)

    async def _email(self, ctx, zone, rec):
        if rec.get("note"):
            return
        spf = analyze_spf(rec["TXT"])
        # follow includes to count lookups (RFC 7208 limit 10) and collect included ranges
        seen, queue, lookups = set(), list(spf["includes"]) + ([spf["redirect"]] if spf.get("redirect") else []), spf["lookups"]
        while queue and len(seen) < 40:
            inc = queue.pop(0)
            if inc in seen:
                continue
            seen.add(inc)
            sub = analyze_spf((await ctx.resolver.query(inc, "TXT")).values("TXT"))
            lookups += sub["lookups"]
            queue += sub["includes"] + ([sub["redirect"]] if sub.get("redirect") else [])
            if ctx.scope.in_scope(inc):
                spf["ip4"] += sub["ip4"]
        spf["total_lookups"] = lookups
        if lookups > 10:
            spf["issues"].append("too_many_dns_lookups")
        dmarc = analyze_dmarc((await ctx.resolver.query(f"_dmarc.{zone}", "TXT")).values("TXT"))
        dk = await asyncio.gather(*(ctx.resolver.query(f"{s}._domainkey.{zone}", "TXT") for s in DKIM_SELECTORS))
        dkim = {}
        for s, a in zip(DKIM_SELECTORS, dk):
            vals = [v for v in a.values("TXT") if "p=" in v or "v=dkim1" in v.lower()]
            if vals:
                m = re.search(r"p=([A-Za-z0-9+/=]*)", vals[0])
                key = m.group(1) if m else ""
                dkim[s] = {"record": vals[0][:300], "key_b64_len": len(key),
                           "weak": 0 < len(key) < 300, "revoked": m is not None and not key}
        rec["email"] = {"spf": spf, "dmarc": dmarc, "dkim": dkim}
        ctx.stats.setdefault("spf_ips", {})[zone] = spf["ip4"] + spf["ip6"]
        has_mx = bool(rec.get("MX"))
        if "missing" in dmarc["issues"]:
            ctx.finding("email_spoofing", "medium" if has_mx else "low", "high", zone, "DMARC record missing",
                        {"spf": spf["records"], "dmarc": None}, self.name, ["email", "spoofing"],
                        next_steps=["Send a spoofed test mail from the domain to a mailbox you control"])
        elif "policy_none" in dmarc["issues"]:
            ctx.finding("email_spoofing", "low", "high", zone, "DMARC policy is p=none (monitoring only)",
                        dmarc["records"], self.name, ["email", "spoofing"])
        if "missing" in spf["issues"] and has_mx:
            ctx.finding("email_spoofing", "low", "high", zone, "SPF record missing on mail-enabled domain", None,
                        self.name, ["email"])
        if "pass_all" in spf["issues"]:
            ctx.finding("email_spoofing", "high", "confirmed", zone, "SPF allows any sender (+all)", spf["records"],
                        self.name, ["email", "spoofing"])
        if "multiple_spf_records" in spf["issues"] or "too_many_dns_lookups" in spf["issues"]:
            ctx.finding("email_spoofing", "low", "high", zone, "SPF permerror (multiple records or >10 lookups)",
                        {"records": spf["records"], "lookups": lookups}, self.name, ["email"])

    async def _nsec_walk(self, ctx, zone, rec):
        try:
            names, info = await ctx.resolver.nsec_walk(zone)
        except Exception as e:  # noqa
            return
        rec["dnssec"] = info
        if info.get("method") == "nsec3":
            rec.setdefault("dnssec", {})["note"] = "NSEC3 in use (hashed; not plaintext-walkable)"
            ctx.finding("dnssec", "info", "high", zone, "Zone uses NSEC3 (DNSSEC) - hashed names present",
                        info, self.name, ["dns", "dnssec", "nsec3"], dedupe_key="nsec3:" + zone,
                        next_steps=["Collect NSEC3 hashes + params and crack offline (nsec3walker/hashcat 8300)"])
            return
        if names:
            n = ctx.add_hosts([x for x in names if ctx.scope.in_scope(x)], "nsec")
            ctx.finding("dns_enum", "medium", "high", zone,
                        f"DNSSEC NSEC zone-walking enumerated {len(names)} names",
                        {"count": len(names), "sample": names[:40], "new_hosts": n, "queries": info["queries"]},
                        self.name, ["dns", "dnssec", "nsec"], dedupe_key="nsec:" + zone,
                        next_steps=["All zone names are now known without brute force"])

    async def _axfr(self, ctx, zone, rec):
        ns_ips = []
        for ns in rec.get("NS", []):
            info = await ctx.resolver.resolve_host(ns)
            ns_ips += [(ns, ip) for ip in info["a"]]
        rec["ns_ips"] = ns_ips
        results = await asyncio.gather(*(ctx.resolver.axfr(ip, zone) for _, ip in ns_ips))
        for (ns, ip), recs in zip(ns_ips, results):
            if not recs:
                continue
            names = sorted({r["name"] for r in recs})
            ctx.emit("axfr", {"zone": zone, "ns": ns, "ip": ip, "records": recs})
            n = ctx.add_hosts(names, "axfr")
            ctx.finding("dns_zone_transfer", "high", "confirmed", zone,
                        f"Zone transfer (AXFR) allowed by {ns} ({ip})",
                        {"ns": ns, "ip": ip, "records": len(recs), "sample": names[:25], "new_hosts": n}, self.name,
                        ["dns", "axfr"], next_steps=[f"dig axfr {zone} @{ip}"])
            break


# ----------------------------------------------------------------------------- brute force + permutations


def load_wordlist(path: Optional[str]) -> List[str]:
    p = path or os.path.join(DATA, "subdomains.txt")
    words = []
    with open(p, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().lower().strip(".")
            if w and not w.startswith("#") and re.match(r"^[a-z0-9_.-]{1,63}$", w):
                words.append(w)
    return list(dict.fromkeys(words))


async def resolve_candidates(ctx, candidates, source: str, log) -> int:
    """Resolve candidate names, drop wildcard hits, add survivors as hosts. Returns number of new hosts."""
    found = 0
    cands = [c for c in candidates if c not in ctx.hosts]
    for i in range(0, len(cands), 5000):
        batch = cands[i:i + 5000]
        res = await gather_limited([ctx.resolver.resolve_host(c) for c in batch], ctx.cfg.dns_concurrency)
        for c, info in zip(batch, res):
            if isinstance(info, Exception):
                continue
            interesting = info["resolved"] or (info["cname"] and info["rcode"] in ("NXDOMAIN", "SERVFAIL")) \
                or info["rcode"] == "SERVFAIL"
            if not interesting or info["rcode"] == "NXDOMAIN" and not info["cname"]:
                continue
            if await is_wildcard_hit(ctx, c, info):
                continue
            if ctx.add_host(c, source):
                found += 1
    log.info("%s: %d candidates -> %d new hosts", source, len(cands), found)
    return found


class Bruteforce(Module):
    name = "brute"
    phase = 25
    mode = "normal"
    description = "Wordlist subdomain brute force with wildcard filtering"

    async def run(self, ctx):
        if not ctx.cfg.brute:
            return
        words = load_wordlist(ctx.cfg.wordlist)
        cands = []
        for root in ctx.scope.roots:
            sig = await wildcard_signature(ctx, root)
            if sig and not sig["ips"] and not sig["cnames"]:
                continue
            cands += [f"{w}.{root}" for w in words]
        await resolve_candidates(ctx, cands, "brute", self.log)


from ..permute import ENV_WORDS, generate as gen_permutations, permute_host


def permutations(host: str, root: str, words=None) -> Set[str]:
    """Permutations of the label(s) left of the root domain (thin wrapper over rcnmstr.permute)."""
    from ..permute import base_words
    return permute_host(host, root, list(words) if words else base_words())


class Permutations(Module):
    name = "permute"
    phase = 26
    mode = "normal"
    loop = True
    description = "Corpus-aware altdns/dnsgen-style permutations of live hosts"

    async def run(self, ctx):
        budget = ctx.cfg.max_permutations - ctx.stats.get("permutations_tried", 0)
        if budget <= 0:
            return
        fresh = [h for h in ctx.live_hosts() if h not in self.done]
        for h in fresh:
            self.done.add(h)
        if not fresh:
            return
        # generate from ALL live hosts (so the corpus is complete) but only when new hosts appeared
        cands = gen_permutations(ctx.live_hosts(), ctx.scope.roots, cap=budget, use_corpus=True)
        cands = [c for c in cands if c not in ctx.hosts]
        ctx.stats["permutations_tried"] = ctx.stats.get("permutations_tried", 0) + len(cands)
        if cands:
            await resolve_candidates(ctx, cands, "permutation", self.log)
