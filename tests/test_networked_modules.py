"""Deterministic coverage for the socket/API modules: portscan, netintel, cloud, origin, CLI, self-test."""
import asyncio
import json
import os
import struct

import pytest

from rcnmstr.context import Config
from rcnmstr.engine import run
from rcnmstr.base import Module

pytestmark_async = pytest.mark.asyncio


def _seed(hosts):
    class Seed(Module):
        name = "netseed"
        mode = "passive"
        phase = 5
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                for h in hosts:
                    ctx.add_host(h, "crtsh")
    return "netseed"


# --------------------------------------------------------------------- portscan
@pytest.mark.asyncio
async def test_portscan_detects_open_ports_and_banner(fake_dns, tmp_path):
    # a fake Redis that answers INFO on a chosen port
    async def banner_svc(reader, writer):
        # greet-on-connect service (like SSH/FTP/SMTP); banner grabber reads without sending
        try:
            writer.write(b"220 ftp.example.com FTP server ready\r\n")
            await writer.drain()
            await asyncio.sleep(0.2)
        except Exception:  # noqa
            pass
        finally:
            writer.close()
    srv = await asyncio.start_server(banner_svc, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    fake_dns.set("db.example.com", "A", ["127.0.0.1"])
    _seed(["db.example.com"])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=["netseed", "resolve", "portscan"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, mode="deep", scan_ports=[port], allow_private=True, timeout=3.0, max_rounds=2)
    try:
        ctx = await run(cfg)
    finally:
        srv.close()
    rec = ctx.ips.get("127.0.0.1")
    assert rec and port in rec["ports"]
    assert port in rec.get("banners", {})
    assert "FTP server ready" in rec["banners"][port]


@pytest.mark.asyncio
async def test_portscan_closed_ports(fake_dns, tmp_path):
    fake_dns.set("x.example.com", "A", ["127.0.0.1"])
    _seed(["x.example.com"])
    # pick a port nothing listens on
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=["netseed", "resolve", "portscan"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, mode="deep", scan_ports=[59999], allow_private=True, timeout=2.0, max_rounds=2)
    ctx = await run(cfg)
    rec = ctx.ips.get("127.0.0.1", {})
    assert 59999 not in rec.get("ports", [])


# --------------------------------------------------------------------- netintel (Cymru via fake DNS)
@pytest.mark.asyncio
async def test_netintel_cymru_and_cdn_range(fake_dns, tmp_path):
    # Team Cymru origin lookup for 8.8.8.8 -> craft TXT answers
    fake_dns.set("8.8.8.8.origin.asn.cymru.com", "TXT", ["15169 | 8.8.8.0/24 | US | arin | 2000-01-01"])
    fake_dns.set("AS15169.asn.cymru.com", "TXT", ["15169 | US | arin | GOOGLE, US"])
    fake_dns.set("host.example.com", "A", ["8.8.8.8"])
    _seed(["host.example.com"])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=["netseed", "resolve", "netintel"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, max_rounds=2, timeout=3.0)
    ctx = await run(cfg)
    rec = ctx.ips.get("8.8.8.8")
    assert rec["asn"] == "15169"
    assert rec["prefix"] == "8.8.8.0/24"
    assert "GOOGLE" in (rec.get("as_name") or "")
    # CDN by range: a Cloudflare IP is classified even without ASN data
    fake_dns.set("cf.example.com", "A", ["104.16.5.5"])


@pytest.mark.asyncio
async def test_netintel_cdn_range_classification(fake_dns, tmp_path):
    fake_dns.set("cf.example.com", "A", ["104.16.5.5"])
    _seed(["cf.example.com"])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=["netseed", "resolve", "netintel"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, max_rounds=2, timeout=3.0)
    ctx = await run(cfg)
    rec = ctx.ips.get("104.16.5.5")
    assert rec.get("cdn_range") == "Cloudflare"
    assert ctx.hosts["cf.example.com"].get("cdn") == "Cloudflare"


# --------------------------------------------------------------------- cloud (S3 against fake server)
@pytest.mark.asyncio
async def test_cloud_public_bucket(fake_dns, tmp_path, monkeypatch):
    # stand up a fake S3 that lists a bucket; monkeypatch the probe fetch URL base via host mapping
    async def s3(reader, writer):
        try:
            req = await asyncio.wait_for(reader.read(2000), 2)
            body = (b'<?xml version="1.0"?><ListBucketResult><Key>secret/db.sql</Key>'
                    b"<Key>backup.zip</Key></ListBucketResult>")
            writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: %d\r\nconnection: close\r\n\r\n%s"
                         % (len(body), body))
            await writer.drain()
        except Exception:  # noqa
            pass
        finally:
            writer.close()
    srv = await asyncio.start_server(s3, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    # point the S3 virtual host at our fake server via the resolver
    fake_dns.wildcards["s3.amazonaws.com"] = ["127.0.0.1"]
    fake_dns.set("storage.googleapis.com", "A", ["127.0.0.1"])

    from rcnmstr.modules import cloud as cloudmod

    # force the bucket candidate to hit our port by rewriting the URL scheme in the module
    orig = cloudmod.CloudAssets._s3

    async def patched_s3(self, ctx, bucket, explicit=False):
        from rcnmstr.http import fetch
        url = f"http://{bucket}.s3.amazonaws.com:{port}/"
        r = await fetch(ctx.probe, url, timeout=ctx.cfg.timeout, max_bytes=200000)
        if r and r.status == 200 and "<ListBucketResult" in r.text:
            import re
            keys = re.findall(r"<Key>([^<]+)</Key>", r.text)
            self._report(ctx, "S3", bucket, url, "public_listing",
                         {"objects_sample": keys}, explicit)
    monkeypatch.setattr(cloudmod.CloudAssets, "_s3", patched_s3)
    monkeypatch.setattr(cloudmod.CloudAssets, "_gcs", lambda self, ctx, b, explicit=False: asyncio.sleep(0))
    monkeypatch.setattr(cloudmod.CloudAssets, "_azure", lambda self, ctx, b, explicit=False: asyncio.sleep(0))
    _seed(["example.com"])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"),
                 modules=["netseed", "resolve", "cloud"], resolvers=[fake_dns.resolver_str], tools=False,
                 brute=False, max_rounds=2, timeout=3.0, max_buckets=50)
    try:
        ctx = await run(cfg)
    finally:
        srv.close()
    buckets = [f for f in ctx.findings.values() if f["type"] == "cloud_bucket"]
    assert any("lists contents" in f["title"] for f in buckets)


# --------------------------------------------------------------------- CLI
def test_cli_list_modules(capsys):
    from rcnmstr.cli import main
    rc = main(["--list-modules"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "passive" in out and "takeover" in out and "analysis" in out


def test_cli_requires_domain(capsys):
    from rcnmstr.cli import main
    with pytest.raises(SystemExit):
        main([])


def test_cli_parse_options():
    from rcnmstr.cli import build_parser
    args = build_parser().parse_args(["a.com", "b.com", "-m", "deep", "--skip", "portscan,cloud",
                                      "--ports", "80,443,8080", "-c", "200"])
    assert args.domains == ["a.com", "b.com"]
    assert args.mode == "deep"


# --------------------------------------------------------------------- self-test harness
@pytest.mark.asyncio
async def test_self_test_runs(tmp_path):
    from rcnmstr.selftest import run_self_test
    rc = await run_self_test(str(tmp_path / "selftest"))
    assert rc == 0
    idx = json.load(open(os.path.join(str(tmp_path / "selftest"), "index.json")))
    assert idx["summary"]["counts"]["findings"] > 10
