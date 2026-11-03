"""Scope handling: root domains, explicit in-scope patterns and exclusions."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import Iterable, List, Optional

# A pragmatic list of multi-label public suffixes. Good enough for registrable-domain extraction
# without shipping the full PSL.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.my", "co.in", "net.in",
    "org.in", "gov.in", "ac.in", "co.za", "org.za", "gov.za", "com.mx", "com.ar", "com.co", "com.tr",
    "co.il", "org.il", "co.id", "or.id", "com.ph", "com.vn", "com.pk", "com.ng", "com.eg", "com.sa",
    "co.th", "in.th", "com.ua", "co.ke", "com.pe", "com.ec", "com.uy", "com.pl", "co.at", "or.at",
    "github.io", "gitlab.io", "herokuapp.com", "azurewebsites.net", "cloudapp.net", "appspot.com",
    "blogspot.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "s3.amazonaws.com",
    "cloudfront.net", "firebaseapp.com", "web.app", "elasticbeanstalk.com", "trafficmanager.net",
    "blob.core.windows.net", "azureedge.net", "myshopify.com", "wordpress.com", "fly.dev",
}

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{1,62}$")


def clean_host(h: str) -> Optional[str]:
    if not h:
        return None
    h = h.strip().lower()
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("/")[0].split("?")[0].split("#")[0]
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    if h.startswith("["):
        return None
    h = h.split(":")[0].strip(".").lstrip("*.").strip()
    while h.startswith("*.") or h.startswith("."):
        h = h[2:] if h.startswith("*.") else h[1:]
    if h.startswith("%2f") or h.startswith("2f"):
        h = h[3:] if h.startswith("%2f") else h
    if not HOST_RE.match(h):
        return None
    return h


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    for n in (3, 2):
        suf = ".".join(parts[-n:])
        if suf in _MULTI_SUFFIXES and len(parts) > n:
            return ".".join(parts[-(n + 1):])
    if ".".join(parts[-2:]) in _MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class Scope:
    def __init__(self, roots: Iterable[str], include: Iterable[str] = (), exclude: Iterable[str] = ()):
        self.roots: List[str] = []
        for r in roots:
            c = clean_host(r)
            if c and c not in self.roots:
                self.roots.append(c)
        self.include = [p.strip().lower() for p in include if p.strip() and not p.startswith("#")]
        self.exclude = [p.strip().lower() for p in exclude if p.strip() and not p.startswith("#")]
        self.include_nets = []
        for p in list(self.include):
            try:
                self.include_nets.append(ipaddress.ip_network(p, strict=False))
                self.include.remove(p)
            except ValueError:
                pass

    @classmethod
    def from_file(cls, roots, path: Optional[str] = None, exclude_path: Optional[str] = None):
        inc, exc = [], []
        if path:
            for line in open(path, encoding="utf-8", errors="ignore"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("!") or line.startswith("-"):
                    exc.append(line[1:])
                else:
                    inc.append(line)
        if exclude_path:
            exc += [x.strip() for x in open(exclude_path, encoding="utf-8", errors="ignore")]
        roots = list(roots)
        # wildcard includes like *.example.com add example.com as root
        for p in inc:
            if p.startswith("*."):
                c = clean_host(p[2:])
                if c and c not in roots:
                    roots.append(c)
        return cls(roots, inc, exc)

    def excluded(self, host: str) -> bool:
        for p in self.exclude:
            if fnmatch.fnmatch(host, p) or host == p.lstrip("*."):
                return True
        return False

    def root_of(self, host: str) -> Optional[str]:
        best = None
        for r in self.roots:
            if host == r or host.endswith("." + r):
                if best is None or len(r) > len(best):
                    best = r
        return best

    def in_scope(self, host: str) -> bool:
        if not host:
            return False
        host = host.lower().rstrip(".")
        if self.excluded(host):
            return False
        if self.root_of(host):
            return True
        for p in self.include:
            if fnmatch.fnmatch(host, p) or host == p:
                return True
        return False

    def ip_in_scope(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.include_nets)

    def extract_hosts(self, text: str) -> set:
        """Find in-scope hostnames inside arbitrary text."""
        out = set()
        if not text:
            return out
        low = text.lower()
        for r in self.roots:
            if r not in low:
                continue
            pat = re.compile(r"(?<![a-z0-9_-])((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*" + re.escape(r) +
                             r")(?![a-z0-9-]|\.[a-z0-9])")
            for m in pat.finditer(low):
                h = clean_host(m.group(1))
                if h and self.in_scope(h):
                    out.add(h)
        return out

    def keywords(self) -> List[str]:
        """Organisation keywords (e.g. 'acme' from acme.co.uk) for bucket/ASN guessing."""
        out = []
        for r in self.roots:
            reg = registrable(r)
            label = reg.split(".")[0]
            if label not in out and len(label) >= 3:
                out.append(label)
        return out
