"""Correlation graph + attack-hypothesis engine tests, driven by synthetic contexts."""
import pytest

from rcnmstr import graph as G
from rcnmstr import hypotheses as HYP
from rcnmstr.scope import Scope


class FakeCtx:
    """Minimal Context stand-in for graph/hypothesis unit tests."""

    def __init__(self):
        self.scope = Scope(["example.com"])
        self.hosts = {}
        self.ips = {}
        self.services = {}
        self.findings = {}

    def add_host(self, h, dns=None, cdn=None, tags=(), waf=None, http=None):
        self.hosts[h] = {"host": h, "dns": dns, "cdn": cdn, "tags": list(tags), "sources": ["test"],
                         "waf": waf, "http": http or []}

    def add_ip(self, ip, **kw):
        self.ips[ip] = {"ip": ip, "hosts": kw.get("hosts", []), "asn": kw.get("asn"),
                        "as_name": kw.get("as_name"), "cdn": kw.get("cdn"), "prefix": kw.get("prefix"),
                        "ptr": [], "ports": kw.get("ports", []), "internetdb": kw.get("internetdb")}

    def add_service(self, url, **kw):
        self.services[url] = {"url": url, "host": kw.get("host"), "scheme": kw.get("scheme", "https"),
                              "port": kw.get("port", 443), "status": kw.get("status", 200),
                              "title": kw.get("title"), "server": kw.get("server"),
                              "simhash": kw.get("simhash"), "tech": kw.get("tech", []),
                              "tls": kw.get("tls"), "favicon_mmh3": kw.get("favicon_mmh3"),
                              "waf": kw.get("waf")}

    def add_finding(self, fid, **kw):
        self.findings[fid] = {"id": fid, "type": kw["type"], "severity": kw.get("severity", "info"),
                              "confidence": kw.get("confidence", "medium"), "target": kw["target"],
                              "title": kw.get("title", kw["type"]), "evidence": kw.get("evidence"),
                              "tags": kw.get("tags", []), "next_steps": kw.get("next_steps", [])}


def test_graph_build_basic():
    c = FakeCtx()
    c.add_host("www.example.com", dns={"resolved": True, "a": ["1.2.3.4"], "aaaa": [], "cname": []})
    c.add_ip("1.2.3.4", asn="13335", as_name="CLOUDFLARENET", prefix="1.2.3.0/24")
    c.add_service("https://www.example.com", host="www.example.com", status=200,
                  tech=[{"name": "Nginx", "category": "web-server"}])
    g = G.build_graph(c)
    assert G.nid("host", "www.example.com") in g.nodes
    assert G.nid("ip", "1.2.3.4") in g.nodes
    assert G.nid("asn", "13335") in g.nodes
    assert G.nid("tech", "Nginx") in g.nodes
    # edges
    assert (G.nid("host", "www.example.com"), G.nid("ip", "1.2.3.4"), "resolves_to") in g.edges
    assert (G.nid("ip", "1.2.3.4"), G.nid("asn", "13335"), "in_asn") in g.edges
    st = g.stats()
    assert st["nodes"] >= 4 and st["edges"] >= 3


def test_graph_dot_renders():
    c = FakeCtx()
    c.add_host("a.example.com", dns={"resolved": True, "a": ["1.1.1.1"], "aaaa": [], "cname": []})
    g = G.build_graph(c)
    dot = g.to_dot()
    assert dot.startswith("digraph recon {") and dot.rstrip().endswith("}")


def test_cert_cluster():
    c = FakeCtx()
    for h in ("www.example.com", "staging.example.com"):
        c.add_host(h, dns={"resolved": True, "a": ["1.1.1.1"], "aaaa": [], "cname": []})
        c.add_service(f"https://{h}", host=h, tls={"fingerprint_sha256": "ABC", "common_name": "*.example.com",
                      "sans": ["www.example.com", "staging.example.com"], "issuer_cn": "R3"})
    g = G.build_graph(c)
    clusters = G.cert_clusters(g)
    assert clusters and set(clusters[0]["hosts"]) >= {"www.example.com", "staging.example.com"}


def test_favicon_and_simhash_clusters():
    c = FakeCtx()
    c.add_service("https://a.example.com", host="a.example.com", favicon_mmh3=12345, simhash=0b1010, status=200)
    c.add_service("https://b.example.com", host="b.example.com", favicon_mmh3=12345, simhash=0b1010, status=403)
    fav = G.favicon_clusters(c)
    assert fav and len(fav[0]["services"]) == 2
    sim = G.simhash_clusters(c, threshold=2)
    assert sim and set(sim[0]["distinct_statuses"]) == {200, 403}


def test_cohosted_ip_cluster():
    c = FakeCtx()
    for i in range(4):
        h = f"h{i}.example.com"
        c.add_host(h, dns={"resolved": True, "a": ["9.9.9.9"], "aaaa": [], "cname": []})
    c.add_ip("9.9.9.9", asn="64500", as_name="ORG")
    g = G.build_graph(c)
    co = G.cohosted_ips(g, min_hosts=3)
    assert co and len(co[0]["hosts"]) == 4


# ---------------------------------------------------------------- hypotheses
def _hyps(c):
    g = G.build_graph(c)
    return HYP.generate(c, g, G.all_clusters(c, g))


def test_hyp_forgotten_origin():
    c = FakeCtx()
    c.add_host("app.example.com", dns={"resolved": True, "a": ["5.5.5.5"], "aaaa": [], "cname": []}, cdn=None)
    c.add_finding("f1", type="content_exposure", severity="high", confidence="high",
                  target="https://app.example.com/.git/HEAD", title="Exposed .git repository",
                  tags=["content", "vcs", "source-leak"])
    hyps = _hyps(c)
    assert any(h["category"] == "forgotten_origin" and "app.example.com" in h["targets"] for h in hyps)
    h = next(h for h in hyps if h["category"] == "forgotten_origin")
    assert h["agent_prompt"] and h["steps"] and 0 < h["confidence"] <= 1


def test_hyp_cdn_bypass():
    c = FakeCtx()
    c.add_host("www.example.com", dns={"resolved": True, "a": ["104.16.1.1"], "aaaa": [], "cname": []},
               cdn="Cloudflare")
    c.add_finding("o1", type="origin_ip_exposure", severity="high", confidence="high",
                  target="www.example.com", title="origin", evidence={"ip": "5.6.7.8"})
    hyps = _hyps(c)
    assert any(h["category"] == "cdn_bypass" and "5.6.7.8" in h["targets"] for h in hyps)


def test_hyp_shadow_staging():
    c = FakeCtx()
    for h in ("www.example.com", "staging.example.com"):
        cdn = "Cloudflare" if h == "www.example.com" else None
        c.add_host(h, dns={"resolved": True, "a": ["1.1.1.1"], "aaaa": [], "cname": []}, cdn=cdn)
        c.add_service(f"https://{h}", host=h, tls={"fingerprint_sha256": "FP1", "common_name": "*.example.com",
                      "sans": ["www.example.com", "staging.example.com"]})
    hyps = _hyps(c)
    ss = [h for h in hyps if h["category"] == "shadow_staging"]
    assert ss and "staging.example.com" in ss[0]["targets"]


def test_hyp_access_control_gap():
    c = FakeCtx()
    c.add_service("https://open.example.com", host="open.example.com", simhash=0b1111000011110000, status=200)
    c.add_service("https://a.example.com", host="a.example.com", simhash=0b1111000011110000, status=403)
    c.add_service("https://b.example.com", host="b.example.com", simhash=0b1111000011110000, status=401)
    for h in ("open", "a", "b"):
        c.add_host(f"{h}.example.com", dns={"resolved": True, "a": ["1.1.1.1"], "aaaa": [], "cname": []})
    hyps = _hyps(c)
    assert any(h["category"] == "access_control_gap" for h in hyps)


def test_hyp_takeover_and_dedup():
    c = FakeCtx()
    c.add_host("shop.example.com", dns={"resolved": False, "a": [], "aaaa": [], "cname": ["x.s3.amazonaws.com"]})
    c.add_finding("t1", type="subdomain_takeover", severity="high", confidence="high",
                  target="shop.example.com", title="Dangling CNAME to AWS/S3", evidence={"service": "AWS/S3"})
    c.add_finding("t2", type="subdomain_takeover", severity="high", confidence="high",
                  target="shop.example.com", title="Dangling CNAME to AWS/S3", evidence={"service": "AWS/S3"})
    hyps = _hyps(c)
    tk = [h for h in hyps if h["category"] == "takeover"]
    assert len(tk) == 1  # deduped


def test_hyp_secret_pivot():
    c = FakeCtx()
    c.add_finding("s1", type="secret", severity="high", confidence="high",
                  target="https://app.example.com/app.js", title="Possible aws_secret_key",
                  evidence={"rule": "aws_secret_key"})
    c.add_finding("b1", type="cloud_bucket", severity="high", confidence="high",
                  target="https://x.s3.amazonaws.com/", title="public bucket")
    hyps = _hyps(c)
    assert any(h["category"] == "secret_pivot" for h in hyps)


def test_hyp_ranking_order():
    c = FakeCtx()
    c.add_finding("a", type="email_spoofing", severity="medium", confidence="high",
                  target="example.com", title="DMARC record missing")
    c.add_host("x.example.com", dns={"resolved": True, "a": ["5.5.5.5"], "aaaa": [], "cname": []})
    c.add_finding("b", type="content_exposure", severity="high", confidence="high",
                  target="https://x.example.com/.env", title="Exposed .env file", tags=["secret", "config"])
    hyps = _hyps(c)
    # highest severity first
    assert hyps[0]["severity"] in ("critical", "high")
    sevs = [h["severity"] for h in hyps]
    assert sevs == sorted(sevs, key=lambda s: -["info", "low", "medium", "high", "critical"].index(s))


def test_hyp_empty_context():
    assert _hyps(FakeCtx()) == []


def test_hyp_sensitive_product():
    c = FakeCtx()
    c.add_finding("tp1", type="tech_identified", severity="info", confidence="medium",
                  target="https://ci.example.com", title="Product identified by favicon hash: Jenkins",
                  evidence={"product": "Jenkins"})
    hyps = _hyps(c)
    assert any(h["category"] == "sensitive_product" and "Jenkins" in h["title"] for h in hyps)
