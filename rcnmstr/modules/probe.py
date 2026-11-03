"""HTTP(S) probing: status, redirects, title, tech fingerprint, favicon hash, TLS cert, security headers, CORS."""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple

from ..base import Module, gather_limited
from ..data.tech import SIGNATURES
from ..http import fetch
from ..scope import clean_host
from ..util import favicon_hash, html_title, is_public_ip, sha1, simhash

import json as _json
import os as _os

_FAVDB = None


def favicon_db(path=None):
    global _FAVDB
    if _FAVDB is None or path:
        p = path or _os.path.join(_os.path.dirname(__file__), "..", "data", "favicons.json")
        try:
            raw = _json.load(open(p, encoding="utf-8"))
            db = {str(k): v for k, v in raw.items() if not k.startswith("_")}
        except Exception:  # noqa
            db = {}
        if path:
            return db
        _FAVDB = db
    return _FAVDB

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy",
                    "cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy"]
LOGIN_HINTS = [r"type=[\"']password[\"']", r"name=[\"']password[\"']", r"login", r"sign in", r"sign-in",
               r"log in", r"username", r"authenticate", r"<title>[^<]*(login|sign in|admin)"]
META_GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_CSP_HOST_RE = re.compile(r"(?:https?:)?//([a-z0-9.\-*]+)", re.I)


def detect_tech(status: int, headers: Dict[str, str], cookies: List[str], body: str) -> List[dict]:
    body_l = body[:400000]
    low = body_l.lower()
    gens = META_GEN_RE.findall(body_l)
    cookie_names = cookies + [c.split("=", 1)[0] for c in cookies]
    found = []
    for name, sig in SIGNATURES.items():
        hit = None
        for h, pat in sig.get("headers", {}).items():
            if h in headers and re.search(pat, headers[h], re.I):
                hit = f"header:{h}"
                break
        if not hit:
            for h in sig.get("header_present", []):
                if h in headers:
                    hit = f"header:{h}"
                    break
        if not hit:
            for pat in sig.get("cookies", []):
                if any(re.search(pat, c, re.I) for c in cookie_names):
                    hit = "cookie"
                    break
        if not hit:
            for pat in sig.get("meta_generator", []):
                if any(re.search(pat, g, re.I) for g in gens):
                    hit = "generator"
                    break
        if not hit:
            for pat in sig.get("body", []):
                try:
                    if re.search(pat, body_l):
                        hit = "body"
                        break
                except re.error:
                    pass
        if not hit:
            for s in sig.get("html", []):
                if s.lower() in low:
                    hit = "html"
                    break
        if hit:
            entry = {"name": name, "category": sig.get("category", ""), "via": hit}
            ver = _extract_version(name, headers, gens, body_l)
            if ver:
                entry["version"] = ver
            if sig.get("cpe"):
                entry["cpe"] = sig["cpe"] + (f":{ver}" if ver else "")
            found.append(entry)
    return found


_VER_RE = re.compile(r"[/ ]v?(\d+(?:\.\d+){1,3})")


def _extract_version(name, headers, gens, body):
    """Best-effort product version from Server/X-Powered-By or a meta generator."""
    probes = []
    low = name.lower()
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if headers.get(h):
            probes.append(headers[h])
    probes += gens
    for p in probes:
        if low.split()[0][:4] in p.lower() or name.split()[0].lower() in p.lower():
            m = _VER_RE.search(p)
            if m:
                return m.group(1)
    # generic: any X.Y in Server header when the tech came from the server header
    for p in probes[:2]:
        m = _VER_RE.search(p)
        if m:
            return m.group(1)
    return None


def parse_cert_der(der: bytes) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_der_x509_certificate(der)
    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except Exception:  # noqa
        pass

    def _name(n):
        try:
            return n.rfc4514_string()
        except Exception:  # noqa
            return str(n)
    out = {"subject": _name(cert.subject), "issuer": _name(cert.issuer), "sans": sans,
           "serial": format(cert.serial_number, "x"), "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex()}
    try:
        out["not_before"] = cert.not_valid_before_utc.isoformat()
        out["not_after"] = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        out["not_before"] = cert.not_valid_before.isoformat()
        out["not_after"] = cert.not_valid_after.isoformat()
    cn = [a.value for a in cert.subject if a.oid._name == "commonName"]
    icn = [a.value for a in cert.issuer if a.oid._name == "commonName"]
    out["common_name"] = cn[0] if cn else None
    out["self_signed"] = cert.subject == cert.issuer
    out["issuer_cn"] = icn[0] if icn else None
    return out


async def get_tls_cert(host: str, ip: str, port: int, timeout: float) -> Optional[dict]:
    ctxssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctxssl.check_hostname = False
    ctxssl.verify_mode = ssl.CERT_NONE
    try:
        ctxssl.set_alpn_protocols(["h2", "http/1.1"])
    except (NotImplementedError, ssl.SSLError):
        pass
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctxssl, server_hostname=host), timeout)
    except (ssl.SSLError, OSError, asyncio.TimeoutError, ValueError):
        return None
    try:
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
        proto = sslobj.version() if sslobj else None
        alpn = sslobj.selected_alpn_protocol() if sslobj else None
        if not der:
            return None
        info = parse_cert_der(der)
        if alpn:
            info["alpn"] = alpn
            info["http2"] = alpn == "h2"
        info["tls_version"] = proto
        return info
    except Exception:  # noqa
        return None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except Exception:  # noqa
            pass


def extract_csp_hosts(csp: str) -> List[str]:
    hosts = set()
    for m in _CSP_HOST_RE.finditer(csp):
        h = clean_host(m.group(1).lstrip("*."))
        if h:
            hosts.add(h)
    return sorted(hosts)


class HTTPProbe(Module):
    name = "probe"
    phase = 50
    mode = "passive"
    loop = True
    description = "Probe http/https services: status, title, tech, favicon hash, TLS, security headers, CORS"

    async def run(self, ctx):
        targets: List[Tuple[str, int, str]] = []
        for h in ctx.live_hosts():
            for port in ctx.cfg.http_ports:
                scheme = "https" if port in (443, 8443) else "http"
                key = (h, port, scheme)
                if key not in self.done:
                    targets.append(key)
        for (hostip, port, scheme) in list(ctx.web_targets):
            if (hostip, port, scheme) not in self.done:
                targets.append((hostip, port, scheme))
        for t in targets:
            self.done.add(t)
        # mark extra web targets as probed so the engine's feedback loop can reach its fixpoint
        probed = getattr(ctx, "_probed_targets", None)
        if probed is None:
            probed = ctx._probed_targets = set()
        probed |= set(ctx.web_targets) & self.done
        await gather_limited([self._probe(ctx, *t) for t in targets], ctx.cfg.concurrency)

    async def _probe(self, ctx, host, port, scheme):
        base = f"{scheme}://{host}" + ("" if port in (80, 443) else f":{port}")
        r = await fetch(ctx.probe, base + "/", allow_redirects=False, timeout=ctx.cfg.timeout, max_bytes=1_500_000)
        if r is None:
            return
        body = r.text
        cookies = r.set_cookies()
        tech = detect_tech(r.status, r.headers, cookies, body)
        title = html_title(body)
        redirect_chain = r.history + ([{"status": r.status, "location": r.header("location")}]
                                      if 300 <= r.status < 400 and r.header("location") else [])
        svc = {"url": base, "input": f"{host}:{port}", "scheme": scheme, "host": host, "port": port,
               "status": r.status, "title": title, "server": r.header("server"),
               "content_type": r.header("content-type"), "content_length": len(r.body),
               "body_sha1": sha1(r.body), "simhash": simhash(body), "elapsed": r.elapsed,
               "tech": tech, "redirects": redirect_chain, "location": r.header("location"),
               "security_headers": {h: r.header(h) for h in SECURITY_HEADERS if r.header(h)},
               "missing_security_headers": [h for h in SECURITY_HEADERS if not r.header(h)],
               "cookies": self._cookie_flags(cookies), "words": len(body.split()), "lines": body.count("\n")}
        csp = r.header("content-security-policy")
        if csp:
            svc["csp_hosts"] = extract_csp_hosts(csp)
            ctx.add_hosts(svc["csp_hosts"], "csp")
        if scheme == "https":
            ip = (ctx.hosts.get(host, {}).get("dns") or {}).get("a", [host])
            ip = ip[0] if ip else host
            cert = await get_tls_cert(host, ip, port, ctx.cfg.timeout)
            if cert:
                svc["tls"] = cert
                ctx.add_hosts([s for s in cert["sans"] if "*" not in s], "tls")
                for s in cert["sans"]:
                    if s.startswith("*."):
                        ctx.add_host(s[2:], "tls")
        # feedback: harvest hosts from body, redirect target, CORS ACAO, set-cookie domains
        self._harvest(ctx, host, body, r)
        await self._cors(ctx, base, svc)
        await self._methods(ctx, base, svc)
        self._judge(ctx, svc, r)
        ctx.services[base] = svc
        rec = ctx.hosts.get(host)
        if rec is not None:
            rec.setdefault("http", []).append({"url": base, "status": r.status, "title": title,
                                               "tech": [t["name"] for t in tech]})
        ctx.emit("service", svc)
        # favicon (separate request, best-effort)
        await self._favicon(ctx, base, svc)

    async def _methods(self, ctx, base, svc):
        r = await fetch(ctx.probe, base + "/", method="OPTIONS", timeout=ctx.cfg.timeout, max_bytes=2000)
        if not r:
            return
        allow = r.header("allow") or r.header("access-control-allow-methods")
        if not allow:
            return
        methods = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
        svc["allowed_methods"] = methods
        dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")]
        if "TRACE" in dangerous:
            ctx.finding("http_methods", "low", "high", base, "HTTP TRACE enabled (Cross-Site Tracing)",
                        {"allow": methods}, self.name, ["methods", "trace"], dedupe_key="trace")
        if any(m in dangerous for m in ("PUT", "DELETE", "PATCH")):
            ctx.finding("http_methods", "low", "medium", base,
                        f"Potentially dangerous HTTP methods advertised: {dangerous}",
                        {"allow": methods}, self.name, ["methods"], dedupe_key="methods",
                        next_steps=["Verify PUT/DELETE actually mutate (many servers advertise but reject)"])

    def _cookie_flags(self, cookies):
        out = []
        for c in cookies:
            name = c.split("=", 1)[0].strip()
            low = c.lower()
            out.append({"name": name, "secure": "secure" in low, "httponly": "httponly" in low,
                        "samesite": (re.search(r"samesite=(\w+)", low) or [None, None])[1]})
        return out

    def _harvest(self, ctx, host, body, r):
        for v in (r.header("location"), r.header("access-control-allow-origin"),
                  r.header("x-pingback"), r.header("link")):
            if v:
                ctx.add_hosts(ctx.scope.extract_hosts(v), "header")
        ctx.add_hosts(ctx.scope.extract_hosts(body[:300000]), "html")

    async def _favicon(self, ctx, base, svc):
        r = await fetch(ctx.probe, base + "/favicon.ico", timeout=ctx.cfg.timeout, max_bytes=200000)
        if r and r.status == 200 and r.body and "image" in r.header("content-type", "image"):
            fh = favicon_hash(r.body)
            svc["favicon_mmh3"] = fh
            svc["favicon_sha1"] = sha1(r.body)
            product = favicon_db().get(str(fh))
            if product:
                svc["favicon_product"] = product
                if not any(t["name"] == product for t in svc.get("tech", [])):
                    svc.setdefault("tech", []).append({"name": product, "category": "favicon-id", "via": "favicon"})
                ctx.finding("tech_identified", "info", "medium", base,
                            f"Product identified by favicon hash: {product}",
                            {"product": product, "favicon_mmh3": fh}, self.name, ["favicon", "fingerprint"],
                            dedupe_key=f"fav:{product}")

    async def _cors(self, ctx, base, svc):
        probe_origin = "https://evil-rcn-poc.com"
        tests = [("reflect", probe_origin), ("null", "null"),
                 ("prefix", f"https://{svc['host']}.evil-rcn-poc.com"),
                 ("suffix", f"https://evil{svc['host']}")]
        for label, origin in tests:
            r = await fetch(ctx.probe, base + "/", headers={"Origin": origin}, timeout=ctx.cfg.timeout,
                            max_bytes=2000)
            if not r:
                continue
            acao = r.header("access-control-allow-origin")
            acac = r.header("access-control-allow-credentials").lower() == "true"
            if not acao:
                continue
            reflected = acao == origin or (acao == "null" and origin == "null")
            if acao == "*" and acac:
                ctx.finding("cors_misconfig", "medium", "high", base, "CORS wildcard with credentials",
                            {"acao": acao, "acac": acac}, self.name, ["cors"])
                return
            if reflected and acac:
                sev = "high" if label in ("reflect", "null") else "medium"
                ctx.finding("cors_misconfig", sev, "high", base,
                            f"CORS reflects attacker origin ({label}) with credentials",
                            {"origin_sent": origin, "acao": acao, "acac": True}, self.name, ["cors"],
                            next_steps=[f"Confirm by requesting with Origin: {origin} and Cookie set"])
                return
            if reflected:
                ctx.finding("cors_misconfig", "low", "medium", base,
                            f"CORS reflects attacker origin ({label}) without credentials",
                            {"origin_sent": origin, "acao": acao}, self.name, ["cors"])
                return

    def _judge(self, ctx, svc, r):
        host, status, url = svc["host"], r.status, svc["url"]
        body = r.text
        if status in (401, 403):
            ctx.tag_host(host, f"http{status}")
            ctx.finding("access_control", "info", "medium", url, f"HTTP {status} (auth/forbidden) - bypass candidate",
                        {"status": status, "server": svc["server"], "www_authenticate": r.header("www-authenticate")},
                        self.name, ["403", "bypass"],
                        next_steps=["Try path/case/method tricks, X-Forwarded-For, X-Original-URL, //, /./, %2e"])
        if any(re.search(p, body, re.I) for p in LOGIN_HINTS) or re.search(r"/(admin|login|signin|wp-login|dashboard)",
                                                                           svc.get("location") or "", re.I):
            if re.search(r"admin|manage|console|dashboard|portal|internal", url, re.I):
                ctx.finding("admin_panel", "info", "medium", url, "Possible admin/login panel",
                            {"title": svc["title"], "status": status}, self.name, ["panel", "auth"])
        if svc.get("tls"):
            import datetime
            try:
                exp = datetime.datetime.fromisoformat(svc["tls"]["not_after"].replace("Z", "+00:00"))
                days = (exp - datetime.datetime.now(datetime.timezone.utc)).days
                svc["tls"]["days_to_expiry"] = days
                if days < 0:
                    ctx.finding("tls_issue", "low", "high", url, "Expired TLS certificate",
                                {"not_after": svc["tls"]["not_after"]}, self.name, ["tls"])
            except Exception:  # noqa
                pass
            if svc["tls"].get("self_signed"):
                ctx.finding("tls_issue", "info", "high", url, "Self-signed TLS certificate",
                            {"subject": svc["tls"]["subject"]}, self.name, ["tls"])
