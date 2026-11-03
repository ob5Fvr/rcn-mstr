"""Favicon hashing (Shodan-compatible) and product-DB identification."""
import pytest

from rcnmstr.util import favicon_hash, murmur3_32
from rcnmstr.modules.probe import favicon_db


def test_favicon_hash_shodan_compat():
    # Shodan favicon hash = mmh3.hash(base64.encodebytes(content)); deterministic + signed int
    data = b"\x00\x01\x02\x03" * 64
    h = favicon_hash(data)
    assert isinstance(h, int)
    assert favicon_hash(data) == h
    assert -2**31 <= h < 2**31


def test_favicon_db_loads():
    db = favicon_db()
    assert isinstance(db, dict) and len(db) >= 20
    assert all(isinstance(k, str) for k in db)
    # known example entries present
    assert "81586312" in db


def test_favicon_db_custom(tmp_path):
    import json
    p = tmp_path / "fav.json"
    p.write_text(json.dumps({"_comment": "x", "12345": "MyApp", "-999": "Other"}))
    db = favicon_db(str(p))
    assert db == {"12345": "MyApp", "-999": "Other"}


@pytest.mark.asyncio
async def test_favicon_identifies_product(fake_dns, tmp_path, monkeypatch):
    import base64
    from rcnmstr.context import Config
    from rcnmstr.engine import run
    from rcnmstr.base import Module
    import asyncio

    # craft favicon bytes and compute their hash, then inject into the DB
    fav = b"JENKINSICON" * 40
    h = favicon_hash(fav)
    import rcnmstr.modules.probe as probemod
    monkeypatch.setattr(probemod, "_FAVDB", {str(h): "Jenkins"})

    async def conn(reader, writer):
        try:
            line = await asyncio.wait_for(reader.readline(), 3)
            path = line.decode().split()[1] if len(line.split()) > 1 else "/"
            while True:
                hl = await asyncio.wait_for(reader.readline(), 3)
                if hl in (b"\r\n", b"\n", b""):
                    break
            if path.startswith("/favicon.ico"):
                body, ct = fav, "image/x-icon"
            else:
                body, ct = b"<html><title>login</title></html>", "text/html"
            out = (f"HTTP/1.1 200 OK\r\ncontent-type: {ct}\r\ncontent-length: {len(body)}\r\n"
                   f"connection: close\r\n\r\n").encode() + body
            writer.write(out)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
    srv = await asyncio.start_server(conn, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    cfg = Config(domains=["example.com"], output=str(tmp_path / "o"), modules=["resolve", "probe"],
                 resolvers=[fake_dns.resolver_str], tools=False, brute=False, max_rounds=2,
                 http_ports=[port], timeout=3.0)
    try:
        ctx = await run(cfg)
    finally:
        srv.close()
    assert any(f["type"] == "tech_identified" and "Jenkins" in f["title"] for f in ctx.findings.values())
    svc = list(ctx.services.values())[0]
    assert svc.get("favicon_product") == "Jenkins"
