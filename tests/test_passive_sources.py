"""Exercise every passive source + the source runner by stubbing api_get."""
import asyncio

import pytest

import rcnmstr.modules.passive as P
from rcnmstr.scope import Scope


class FakeCtx:
    def __init__(self, keys=None):
        self.scope = Scope(["example.com"])
        self.hosts = {}
        self.pending_hosts = set()
        self.stats = {}
        self.round = 1
        self.api = object()
        self._keys = keys or {}

        class C:
            tools = False
        self.cfg = C()

    def key(self, name):
        return self._keys.get(name.lower())

    def add_host(self, h, src):
        from rcnmstr.scope import clean_host
        c = clean_host(h)
        if c and self.scope.in_scope(c) and c not in self.hosts:
            self.hosts[c] = {"sources": [src]}
            return True
        return False

    def add_hosts(self, hosts, src):
        return sum(1 for h in hosts if self.add_host(h, src))

    def emit(self, *a, **k):
        pass


# canned responses keyed by URL substring
CANNED = {
    "crt.sh": [{"name_value": "a.example.com\n*.b.example.com", "common_name": "c.example.com"}],
    "certspotter": [{"dns_names": ["cs.example.com", "cs2.example.com"]}],
    "hackertarget": "ht.example.com,1.2.3.4\nht2.example.com,5.6.7.8",
    "otx.alienvault.com/api/v1/indicators/domain": {"passive_dns": [{"hostname": "otx.example.com", "address": "1.1.1.1"}]},
    "urlscan.io/api/v1/search": {"results": [{"page": {"domain": "us.example.com", "url": "https://us.example.com/x"}}]},
    "jldc.me": ["anubis.example.com", "anubis2.example.com"],
    "rapiddns.io": "<html>rd.example.com and rd2.example.com</html>",
    "subdomain.center": ["sc.example.com"],
    "columbus.elmasy.com": ["col", "col2"],
    "virustotal.com": {"data": [{"id": "vt.example.com"}], "links": {}},
    "securitytrails.com": {"subdomains": ["st", "st2"]},
    "projectdiscovery.io": {"subdomains": ["chaos"]},
    "api.shodan.io": {"subdomains": ["sh"], "data": []},
    "fullhunt.io": {"hosts": ["fh.example.com"]},
    "api.github.com/search/code": {"items": [{"text_matches": [{"fragment": "see gh.example.com here"}],
                                              "repository": {"full_name": "o/r"}, "path": "a", "html_url": "u"}]},
}


def _fake_api_get(as_json=True):
    async def fake(session, url, params=None, headers=None, **kw):
        # paginated sources: only return data for the first page to end loops promptly
        if (params or {}).get("page", 1) not in (1, None):
            return None
        for key, val in CANNED.items():
            if key in url:
                if isinstance(val, str) and kw.get("as_json") is False or (not kw.get("as_json", True)):
                    return val if isinstance(val, str) else None
                return val
        return None
    return fake


@pytest.mark.asyncio
async def test_all_keyless_sources(monkeypatch):
    monkeypatch.setattr(P, "api_get", _fake_api_get())
    ctx = FakeCtx()
    await P.PassiveSubdomains().run(ctx)
    hosts = set(ctx.hosts)
    # from various keyless sources
    for expected in ("a.example.com", "c.example.com", "cs.example.com", "ht.example.com",
                     "otx.example.com", "us.example.com", "anubis.example.com", "rd.example.com",
                     "sc.example.com", "col.example.com"):
        assert expected in hosts, f"missing {expected}"
    # key-gated sources skipped without keys
    assert ctx.stats["sources"]["virustotal"]["status"].startswith("skipped")


@pytest.mark.asyncio
async def test_key_gated_sources(monkeypatch):
    monkeypatch.setattr(P, "api_get", _fake_api_get())
    ctx = FakeCtx(keys={"virustotal_key": "k", "securitytrails_key": "k", "chaos_key": "k",
                        "shodan_key": "k", "fullhunt_key": "k", "github_token": "k"})
    await P.PassiveSubdomains().run(ctx)
    hosts = set(ctx.hosts)
    assert "vt.example.com" in hosts
    assert "st.example.com" in hosts
    assert "chaos.example.com" in hosts
    assert "fh.example.com" in hosts
    assert "gh.example.com" in hosts


@pytest.mark.asyncio
async def test_source_error_recorded(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("nope")
    monkeypatch.setattr(P, "api_get", boom)
    ctx = FakeCtx()
    await P.PassiveSubdomains().run(ctx)  # must not raise
    statuses = [s["status"] for s in ctx.stats["sources"].values()]
    assert any("error" in s or "empty" in s for s in statuses)


def test_parse_helpers_direct():
    assert "a.example.com" in P.parse_crtsh([{"name_value": "a.example.com"}])
    assert P.parse_hackertarget("h,1.2.3.4") == [("h", "1.2.3.4")]
    assert P.parse_list({"subdomains": ["x"]}) == ["x"]
    assert P.labels_to_hosts(["api"], "example.com") == ["api.example.com"]
