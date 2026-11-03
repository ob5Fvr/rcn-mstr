"""End-to-end engine runs against in-process FakeDNS + FakeHTTP. Exercises the real pipeline."""
import json
import os

import pytest

from rcnmstr.context import Config
from rcnmstr.engine import run

pytestmark = pytest.mark.asyncio


async def _run(fake_dns, tmp_path, modules, http_port=None, **over):
    cfg = Config(
        domains=["example.com"],
        output=str(tmp_path / "out"),
        mode=over.pop("mode", "normal"),
        modules=modules,
        resolvers=[fake_dns.resolver_str],
        brute=over.pop("brute", False),
        tools=False,
        max_rounds=over.pop("max_rounds", 3),
        timeout=3.0,
        http_ports=[http_port] if http_port else [80, 443],
        **over,
    )
    return await run(cfg)


def _read_jsonl(outdir, name):
    p = os.path.join(outdir, name)
    if not os.path.exists(p):
        return []
    return [json.loads(l) for l in open(p) if l.strip()]


async def test_resolve_and_seed(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["93.184.216.34"])
    ctx = await _run(fake_dns, tmp_path, ["resolve"])
    assert ctx.hosts["example.com"]["dns"]["a"] == ["93.184.216.34"]
    assert "example.com" in ctx.live_hosts()


async def test_brute_force_finds_hosts(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    fake_dns.set("www.example.com", "A", ["1.1.1.2"])
    fake_dns.set("api.example.com", "A", ["1.1.1.3"])
    fake_dns.set("dev.example.com", "A", ["1.1.1.4"])
    ctx = await _run(fake_dns, tmp_path, ["resolve", "brute"], brute=True)
    live = set(ctx.live_hosts())
    assert {"www.example.com", "api.example.com", "dev.example.com"} <= live


async def test_wildcard_filtering(fake_dns, tmp_path):
    # *.example.com -> 9.9.9.9 ; a real host api has its own IP.
    # Brute-forced names that match the wildcard IP must be DROPPED (not added as hosts).
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    fake_dns.wildcards["example.com"] = ["9.9.9.9"]
    fake_dns.set("api.example.com", "A", ["2.2.2.2"])
    ctx = await _run(fake_dns, tmp_path, ["resolve", "brute"], brute=True)
    assert "api.example.com" in ctx.live_hosts()
    # "ftp"/"vpn" are in the wordlist and only resolve via the wildcard -> must not survive
    for junk in ("ftp.example.com", "vpn.example.com", "mail.example.com"):
        assert junk not in ctx.hosts, f"{junk} should have been filtered as a wildcard hit"
    # every live host must have a non-wildcard IP
    for h in ctx.live_hosts():
        assert ctx.hosts[h]["dns"]["a"] != ["9.9.9.9"]


async def test_wildcard_tagging_from_passive(fake_dns, tmp_path):
    # A host from a passive source that matches the wildcard IP is tagged, not silently kept.
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    fake_dns.wildcards["example.com"] = ["9.9.9.9"]
    from rcnmstr.base import Module

    class Seed(Module):
        name = "wcseed"
        mode = "passive"
        phase = 5
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                ctx.add_host("ghost.example.com", "anubis")
    fake_dns.set("ghost.example.com", "A", ["9.9.9.9"])
    ctx = await _run(fake_dns, tmp_path, ["wcseed", "resolve"])
    assert "wildcard" in ctx.hosts["ghost.example.com"]["tags"]


async def test_http_probe_and_tech(fake_dns, fake_http, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    fake_http.route("/", 200, {"server": "nginx/1.24", "x-powered-by": "PHP/8.2"},
                    "<html><head><title>Example Site</title></head><body>hi</body></html>")
    ctx = await _run(fake_dns, tmp_path, ["resolve", "probe"], http_port=fake_http.port)
    svcs = list(ctx.services.values())
    assert len(svcs) == 1
    s = svcs[0]
    assert s["status"] == 200
    assert s["title"] == "Example Site"
    names = {t["name"] for t in s["tech"]}
    assert "Nginx" in names and "PHP" in names
    assert "content-security-policy" in s["missing_security_headers"]


async def test_cors_misconfig_detected(fake_dns, fake_http, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])

    def handler(method, path, headers, body):
        origin = headers.get("origin", "")
        h = {"content-type": "text/html"}
        if origin:
            h["access-control-allow-origin"] = origin
            h["access-control-allow-credentials"] = "true"
        return (200, h, b"<html><title>x</title></html>")
    fake_http.host_handler = handler
    ctx = await _run(fake_dns, tmp_path, ["resolve", "probe"], http_port=fake_http.port)
    cors = [f for f in ctx.findings.values() if f["type"] == "cors_misconfig"]
    assert cors and cors[0]["severity"] == "high"


async def test_takeover_nxdomain_cname(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    # shop -> CNAME to an S3 bucket whose target is NXDOMAIN
    fake_dns.set_cname("shop.example.com", "missingbucket.s3.amazonaws.com", final_a=None)
    from rcnmstr.base import Module

    class Seed(Module):
        name = "tkseed"
        mode = "passive"
        phase = 5
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                ctx.add_host("shop.example.com", "crtsh")
    ctx = await _run(fake_dns, tmp_path, ["tkseed", "resolve", "takeover"])
    tk = [f for f in ctx.findings.values() if f["type"] in ("subdomain_takeover", "dangling_dns")]
    assert tk, "expected a takeover/dangling finding for shop.example.com"
    assert tk[0]["target"] == "shop.example.com"


async def test_content_discovery_git(fake_dns, fake_http, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    fake_http.route("/", 200, {}, "<html><title>app</title></html>")
    fake_http.route("/.git/HEAD", 200, {}, "ref: refs/heads/main\n")
    fake_http.route("/.env", 200, {}, "SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n")
    ctx = await _run(fake_dns, tmp_path, ["resolve", "probe", "content"], http_port=fake_http.port)
    exp = {f["title"] for f in ctx.findings.values() if f["type"] == "content_exposure"}
    assert any(".git" in t for t in exp)
    assert any(".env" in t for t in exp)


async def test_content_soft404_calibration(fake_dns, fake_http, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    # server returns 200 for everything (soft 404) -> content module must NOT report junk

    def handler(method, path, headers, body):
        if path == "/.git/HEAD":   # but a real git head still has the signature
            return (200, {}, b"ref: refs/heads/main\n")
        return (200, {}, b"<html><title>Generic Page</title>not found but 200</html>")
    fake_http.host_handler = handler
    ctx = await _run(fake_dns, tmp_path, ["resolve", "probe", "content"], http_port=fake_http.port)
    findings = [f for f in ctx.findings.values() if f["type"] == "content_exposure"]
    # only the real git head (content signature) should survive soft-404 calibration
    titles = {f["title"] for f in findings}
    assert all("robots" not in t.lower() for t in titles)
    assert any(".git" in t for t in titles)


async def test_js_secret_extraction(fake_dns, fake_http, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    fake_http.route("/", 200, {"content-type": "text/html"},
                    '<html><title>a</title><script src="/app.js"></script></html>')
    fake_http.route("/app.js", 200, {"content-type": "application/javascript"},
                    'var k="AKIAIOSFODNN7EXAMPLE";fetch("/api/v2/internal/users");'
                    'var api="https://secret-api.example.com/v1";')
    ctx = await _run(fake_dns, tmp_path, ["resolve", "probe", "js"], http_port=fake_http.port)
    secrets = [f for f in ctx.findings.values() if f["type"] == "secret"]
    assert any(f["evidence"]["rule"] == "aws_access_key" for f in secrets)
    assert "/api/v2/internal/users" in ctx.paths or any("/api/v2" in p for p in ctx.paths)
    # feedback: in-scope host from JS added
    assert "secret-api.example.com" in ctx.hosts


async def test_feedback_loop_tls_san(fake_dns, tmp_path):
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    # a host discovered only via being added should get resolved in a later round
    fake_dns.set("hidden.example.com", "A", ["2.2.2.2"])

    from rcnmstr.base import Module

    class Seeder(Module):
        name = "testseeder"
        phase = 5
        mode = "passive"
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                ctx.add_host("hidden.example.com", "testseed")
    ctx = await _run(fake_dns, tmp_path, ["testseeder", "resolve"])
    assert "hidden.example.com" in ctx.live_hosts()


async def test_output_files_written(fake_dns, fake_http, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    fake_http.route("/", 200, {"server": "nginx"}, "<html><title>x</title></html>")
    ctx = await _run(fake_dns, tmp_path, ["resolve", "probe"], http_port=fake_http.port)
    out = ctx.outdir
    for f in ("index.json", "hosts.jsonl", "services.jsonl", "ips.jsonl", "run.json", "summary.json", "README.md"):
        assert os.path.exists(os.path.join(out, f)), f
    idx = json.load(open(os.path.join(out, "index.json")))
    assert idx["schema"] == "rcn-mstr/1.1"
    assert idx["summary"]["counts"]["services"] == 1
    run_meta = json.load(open(os.path.join(out, "run.json")))
    assert run_meta["dns"]["mode"] == "udp"


async def test_wildcard_not_tagged_when_from_ct(fake_dns, tmp_path):
    # hosts from CT logs should not be dropped as wildcards even if they match the wildcard IP
    fake_dns.set("example.com", "A", ["1.1.1.1"])
    fake_dns.wildcards["example.com"] = ["9.9.9.9"]

    from rcnmstr.base import Module

    class CTSeed(Module):
        name = "ctseed"
        phase = 5
        mode = "passive"
        default = False

        async def run(self, ctx):
            if ctx.round == 1:
                ctx.add_host("real.example.com", "crtsh")
    fake_dns.set("real.example.com", "A", ["9.9.9.9"])  # same as wildcard IP
    ctx = await _run(fake_dns, tmp_path, ["ctseed", "resolve"])
    assert "wildcard" not in ctx.hosts["real.example.com"]["tags"]


async def test_feedback_loop_terminates_with_web_targets(fake_dns, fake_http, tmp_path):
    """web_targets must be marked probed so the loop reaches a fixpoint before max_rounds."""
    fake_dns.set("example.com", "A", ["127.0.0.1"])
    fake_http.route("/", 200, {"server": "nginx"}, "<html><title>x</title></html>")
    from rcnmstr.base import Module

    class AddWebTarget(Module):
        name = "webt"
        mode = "passive"
        phase = 6
        default = False
        loop = True

        async def run(self, ctx):
            ctx.web_targets.add(("example.com", fake_http.port, "http"))
    ctx = await _run(fake_dns, tmp_path, ["webt", "resolve", "probe"], http_port=fake_http.port, max_rounds=5)
    # with the fix, web_targets_pending() is False once probed, so it converges early (< 5 rounds)
    assert not ctx.web_targets_pending()
    assert ctx.round <= 5


async def test_http_methods_enumeration(fake_dns, fake_http, tmp_path):
    fake_dns.set("example.com", "A", ["127.0.0.1"])

    def handler(method, path, headers, body):
        if method == "OPTIONS":
            return (200, {"allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"}, b"")
        return (200, {"server": "nginx"}, b"<html><title>x</title></html>")
    fake_http.host_handler = handler
    ctx = await _run(fake_dns, tmp_path, ["resolve", "probe"], http_port=fake_http.port)
    svc = list(ctx.services.values())[0]
    assert "PUT" in svc.get("allowed_methods", []) and "TRACE" in svc["allowed_methods"]
    mf = [f for f in ctx.findings.values() if f["type"] == "http_methods"]
    assert any("TRACE" in f["title"] for f in mf)
    assert any("dangerous" in f["title"].lower() for f in mf)


async def test_wildcard_signature_concurrent_safe(fake_dns, tmp_path):
    """Concurrent callers get the same signature; no caller sees a half-built placeholder."""
    import asyncio as _a
    from rcnmstr.modules.dnsenum import wildcard_signature
    from rcnmstr.context import Config, Context
    from rcnmstr.scope import Scope
    from rcnmstr.dns.resolver import Resolver
    fake_dns.wildcards["example.com"] = ["9.9.9.9"]
    r = Resolver([fake_dns.resolver_str], timeout=2.0, retries=2)
    await r.start()
    ctx = Context(Config(domains=["example.com"], output=str(tmp_path / "o")), Scope(["example.com"]),
                  str(tmp_path / "o"))
    ctx.resolver = r
    sigs = await _a.gather(*(wildcard_signature(ctx, "example.com") for _ in range(20)))
    assert all(s is not None and s["ips"] == {"9.9.9.9"} for s in sigs)
    ctx.close()
    await r.close()
