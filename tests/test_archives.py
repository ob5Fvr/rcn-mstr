"""Archive URL harvesting, uro-dedup, gf-classification, param/path extraction."""
import os

import pytest

import rcnmstr.modules.archives as A
from rcnmstr.scope import Scope


class FakeCtx:
    def __init__(self, outdir, recheck=False):
        self.scope = Scope(["example.com"])
        self.hosts = {}
        self.params = set()
        self.paths = set()
        self.stats = {}
        self.findings = {}
        self.outdir = outdir
        self.api = object()
        self.probe = object()
        self.round = 1

        class C:
            archive_limit = 50000
            recheck_archive = recheck
            timeout = 3.0
            concurrency = 10
        self.cfg = C()
        os.makedirs(outdir, exist_ok=True)

    def add_hosts(self, hosts, src):
        from rcnmstr.scope import clean_host
        n = 0
        for h in hosts:
            c = clean_host(h)
            if c and self.scope.in_scope(c) and c not in self.hosts:
                self.hosts[c] = {"sources": [src]}
                n += 1
        return n

    def add_host(self, h, src):
        return self.add_hosts([h], src) > 0

    def emit(self, *a, **k):
        pass

    def finding(self, *a, **k):
        self.findings[a[0] + str(a[4])] = a

    def write_lines(self, name, lines):
        with open(os.path.join(self.outdir, name), "w") as fh:
            fh.write("\n".join(map(str, lines)))


WAYBACK = [["original"],
           ["https://a.example.com/p?id=1&redirect=http://x"],
           ["https://a.example.com/p?id=2&redirect=http://y"],   # dupe after uro
           ["https://a.example.com/backup.sql"],
           ["https://sub.example.com/app?url=http://ssrf"]]


def _fake_api_get(monkeypatch):
    async def fake(session, url, params=None, headers=None, as_json=True, **kw):
        if "web.archive.org" in url:
            return WAYBACK
        if "collinfo.json" in url:
            return [{"cdx-api": "https://index.commoncrawl.org/CC-MAIN-cdx"}]
        if "CC-MAIN-cdx" in url:
            return '{"url": "https://cc.example.com/x?q=1"}'
        if "otx" in url:
            return {"url_list": [{"url": "https://otx.example.com/a"}], "has_next": False}
        if "urlscan" in url:
            return {"results": [{"page": {"url": "https://us.example.com/y?file=/etc/passwd"}}]}
        return None
    monkeypatch.setattr(A, "api_get", fake)


@pytest.mark.asyncio
async def test_archives_harvest_dedupe_classify(tmp_path, monkeypatch):
    _fake_api_get(monkeypatch)
    ctx = FakeCtx(str(tmp_path / "o"))
    await A.Archives().run(ctx)
    # hosts fed back
    assert "a.example.com" in ctx.hosts and "sub.example.com" in ctx.hosts
    assert "cc.example.com" in ctx.hosts and "otx.example.com" in ctx.hosts
    # uro dedup collapsed the two id/redirect URLs
    stats = ctx.stats["archive_urls"]
    assert stats["raw"] >= 5 and stats["deduped"] < stats["raw"]
    # params + classification findings
    assert "redirect" in ctx.params or "id" in ctx.params
    types = {k.split("ctx")[0] for k in ctx.findings}
    assert any("archive_params" in k for k in ctx.findings)
    # files written
    assert os.path.exists(os.path.join(ctx.outdir, "urls_all.txt"))


def test_uro_key():
    assert A.uro_key("https://x.com/u/1/p?id=5") == A.uro_key("https://x.com/u/999/p?id=9")


def test_classify_interesting_ext():
    t = A.classify("https://x.com/db.backup.sql")
    assert "interesting_ext" in t
    t2 = A.classify("https://x.com/a?redirect=1&cmd=ls")
    assert "redirect" in t2 and "rce" in t2
