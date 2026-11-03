"""Cloud bucket discovery/exposure logic for S3/GCS/Azure/DO."""
import pytest

import rcnmstr.modules.cloud as C


class Resp:
    def __init__(self, status, text):
        self.status = status
        self._t = text

    @property
    def text(self):
        return self._t


class Ctx:
    def __init__(self):
        self.findings = {}
        self.cloud_refs = set()
        self.probe = object()
        self.hosts = {}

        class Cfg:
            timeout = 3.0
            concurrency = 10
            max_buckets = 100
        self.cfg = Cfg()

        class Scope:
            roots = ["example.com"]

            def keywords(self):
                return ["acme"]
        self.scope = Scope()
        self.resolver = None

    def finding(self, type, sev, conf, target, title, ev, mod, tags, dedupe_key=None, next_steps=None):
        self.findings[target] = {"type": type, "severity": sev, "title": title, "ev": ev}


def test_candidate_names_and_ref():
    names = C.candidate_names(["acme"])
    assert "acme" in names and "acme-prod" in names
    assert C.parse_ref("https://b.s3.amazonaws.com/x") == ("s3", "b")


@pytest.mark.asyncio
async def test_s3_public_listing(monkeypatch):
    async def fake_fetch(sess, url, **kw):
        return Resp(200, '<ListBucketResult><Key>secret.sql</Key><Key>db.bak</Key></ListBucketResult>')
    monkeypatch.setattr(C, "fetch", fake_fetch)
    ctx = Ctx()
    await C.CloudAssets()._s3(ctx, "acme-backups", explicit=True)
    f = [v for v in ctx.findings.values() if v["type"] == "cloud_bucket"]
    assert f and "lists contents" in f[0]["title"]
    assert "secret.sql" in str(f[0]["ev"])


@pytest.mark.asyncio
async def test_s3_private(monkeypatch):
    async def fake_fetch(sess, url, **kw):
        return Resp(403, "<Error><Code>AccessDenied</Code></Error>")
    monkeypatch.setattr(C, "fetch", fake_fetch)
    ctx = Ctx()
    await C.CloudAssets()._s3(ctx, "acme", explicit=True)
    assert any("access denied" in v["title"].lower() for v in ctx.findings.values())


@pytest.mark.asyncio
async def test_gcs_public(monkeypatch):
    async def fake_fetch(sess, url, **kw):
        return Resp(200, '<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>')
    monkeypatch.setattr(C, "fetch", fake_fetch)
    ctx = Ctx()
    await C.CloudAssets()._gcs(ctx, "acme-data", explicit=False)
    assert any(v["type"] == "cloud_bucket" for v in ctx.findings.values())


@pytest.mark.asyncio
async def test_azure_nxdomain_takeover(monkeypatch):
    class R:
        async def resolve_host(self, name):
            return {"resolved": False, "a": [], "aaaa": [], "cname": [], "rcode": "NXDOMAIN"}
    ctx = Ctx()
    ctx.resolver = R()
    await C.CloudAssets()._azure(ctx, "acmestorage", explicit=True)
    assert any("NXDOMAIN" in str(v["ev"]) or "takeover" in v["title"].lower()
               or "claimable" in v["title"].lower() for v in ctx.findings.values())
