"""Pure-function tests across modules: parsers, analyzers, classifiers, signatures."""
import pytest

from rcnmstr.modules import passive, dnsenum, takeover, netintel, probe, archives, cloud, jsanalysis, content


# ------------------------------------------------------------------ passive parsers
def test_parse_crtsh():
    data = [{"name_value": "a.example.com\n*.b.example.com", "common_name": "c.example.com"}]
    out = passive.parse_crtsh(data)
    assert "a.example.com" in out and "*.b.example.com" in out and "c.example.com" in out


def test_parse_hackertarget():
    assert passive.parse_hackertarget("a.example.com,1.2.3.4\nb.example.com,5.6.7.8") == \
        [("a.example.com", "1.2.3.4"), ("b.example.com", "5.6.7.8")]
    assert passive.parse_hackertarget("error: API count exceeded") == []


def test_parse_otx_and_urlscan():
    assert passive.parse_otx({"passive_dns": [{"hostname": "x.example.com", "address": "1.1.1.1"}]}) == \
        [("x.example.com", "1.1.1.1")]
    u = passive.parse_urlscan({"results": [{"page": {"domain": "a.example.com", "url": "https://a.example.com/x"}}]})
    assert "a.example.com" in u


def test_labels_to_hosts():
    assert set(passive.labels_to_hosts(["api", "www.example.com"], "example.com")) == \
        {"api.example.com", "www.example.com"}


# ------------------------------------------------------------------ SPF / DMARC
def test_spf_pass_all():
    r = dnsenum.analyze_spf(["v=spf1 include:_spf.google.com +all"])
    assert "pass_all" in r["issues"] and r["all"] == "+all"
    assert "_spf.google.com" in r["includes"]


def test_spf_missing_and_softfail():
    assert "missing" in dnsenum.analyze_spf([])["issues"]
    assert "softfail_all" in dnsenum.analyze_spf(["v=spf1 ~all"])["issues"]
    r = dnsenum.analyze_spf(["v=spf1 ip4:1.2.3.0/24 ip4:5.6.7.8 -all"])
    assert r["ip4"] == ["1.2.3.0/24", "5.6.7.8"] and r["all"] == "-all"


def test_dmarc():
    assert "missing" in dnsenum.analyze_dmarc([])["issues"]
    assert "policy_none" in dnsenum.analyze_dmarc(["v=DMARC1; p=none; rua=mailto:x@y.com"])["issues"]
    r = dnsenum.analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:x@y.com; pct=50"])
    assert "pct_below_100" in r["issues"] and r["tags"]["p"] == "reject"
    assert "no_aggregate_reporting" in dnsenum.analyze_dmarc(["v=DMARC1; p=quarantine"])["issues"]


# ------------------------------------------------------------------ permutations
def test_permutations():
    out = dnsenum.permutations("api.example.com", "example.com")
    assert "dev-api.example.com" in out
    assert "api-dev.example.com" in out
    assert "dev.api.example.com" in out
    assert "api.example.com" not in out  # never itself


def test_permutations_number_increment():
    out = dnsenum.permutations("web1.example.com", "example.com")
    assert "web2.example.com" in out


def test_permutations_word_swap():
    out = dnsenum.permutations("api-dev.example.com", "example.com")
    assert "api-stg.example.com" in out or "api-staging.example.com" in out


def test_wordlist_loads():
    wl = dnsenum.load_wordlist(None)
    assert len(wl) > 900
    assert "www" in wl and "api" in wl and "dev" in wl
    assert len(wl) == len(set(wl))  # deduped


# ------------------------------------------------------------------ takeover
def test_takeover_match_service():
    fps, _ = takeover.load_fingerprints()
    s3 = takeover.match_service(["mybucket.s3.amazonaws.com"], fps)
    assert any(f["service"] == "AWS/S3" for f in s3)
    gh = takeover.match_service(["user.github.io"], fps)
    assert any("Github" in f["service"] for f in gh)


def test_takeover_body_match():
    fps, _ = takeover.load_fingerprints()
    gh = next(f for f in fps if f["service"] == "Github")
    assert takeover.body_matches(gh, 404, "There isn't a GitHub Pages site here.")
    assert not takeover.body_matches(gh, 200, "welcome to my site")


def test_takeover_http_status_fingerprint():
    fps, _ = takeover.load_fingerprints()
    hr = next((f for f in fps if f["service"] == "Helprace"), None)
    if hr:
        assert takeover.body_matches(hr, 301, "")


# ------------------------------------------------------------------ netintel classifiers
def test_cdn_cname():
    assert netintel.classify_cdn_cname(["x.cloudfront.net"]) == "AWS/CloudFront"
    assert netintel.classify_cdn_cname(["foo.fastly.net"]) == "Fastly"
    assert netintel.classify_cdn_cname(["nothing.example.com"]) is None


def test_cdn_headers():
    assert netintel.classify_cdn_headers({"cf-ray": "abc"}) == "Cloudflare"
    assert netintel.classify_cdn_headers({"x-amz-cf-id": "z"}) == "AWS/CloudFront"
    assert netintel.classify_cdn_headers({"server": "nginx"}) is None


def test_cdn_asn():
    assert netintel.classify_cdn_asn("CLOUDFLARENET, US") == "Cloudflare"
    assert netintel.classify_cdn_asn("AKAMAI-AS, US") == "Akamai"
    assert netintel.classify_cdn_asn("SOME-CORP-AS") is None


# ------------------------------------------------------------------ probe tech detection
def test_detect_tech_headers():
    tech = probe.detect_tech(200, {"server": "nginx/1.18", "x-powered-by": "PHP/8.1"}, [], "")
    names = {t["name"] for t in tech}
    assert "Nginx" in names and "PHP" in names


def test_detect_tech_body_and_cookie():
    tech = probe.detect_tech(200, {}, ["wordpress_logged_in=1"],
                             '<meta name="generator" content="WordPress 6.4"><link href="/wp-content/x">')
    assert "WordPress" in {t["name"] for t in tech}
    tech2 = probe.detect_tech(200, {}, ["laravel_session=abc"], "")
    assert "Laravel" in {t["name"] for t in tech2}


def test_extract_csp_hosts():
    hosts = probe.extract_csp_hosts("default-src 'self' https://cdn.example.com http://*.api.example.com")
    assert "cdn.example.com" in hosts and "api.example.com" in hosts


# ------------------------------------------------------------------ archives
def test_uro_key_collapses():
    a = archives.uro_key("https://x.com/user/123/profile?id=5&name=a")
    b = archives.uro_key("https://x.com/user/999/profile?id=7&name=b")
    assert a == b


def test_uro_uuid_hash():
    a = archives.uro_key("https://x.com/f/550e8400-e29b-41d4-a716-446655440000/view")
    b = archives.uro_key("https://x.com/f/550e8400-e29b-41d4-a716-446655449999/view")
    assert a == b


def test_classify_params():
    tags = archives.classify("https://x.com/p?redirect=http://evil&id=1")
    assert "redirect" in tags and "sqli" in tags
    tags2 = archives.classify("https://x.com/backup.sql")
    assert "interesting_ext" in tags2


# ------------------------------------------------------------------ cloud
def test_candidate_names():
    names = cloud.candidate_names(["acme"])
    assert "acme" in names and "acme-backup" in names and "dev-acme" in names
    assert all(cloud.BUCKET_NAME_RE.match(n) for n in names)


def test_parse_ref():
    assert cloud.parse_ref("https://mybucket.s3.amazonaws.com/x") == ("s3", "mybucket")
    assert cloud.parse_ref("foo.blob.core.windows.net") == ("azure", "foo")
    assert cloud.parse_ref("storage.googleapis.com/mybkt") == ("gcs", "mybkt")


# ------------------------------------------------------------------ secrets
def test_secret_extraction():
    text = 'aws_key = "AKIAIOSFODNN7EXAMPLE"; const token="ghp_' + "a" * 36 + '";'
    secrets = jsanalysis.extract_secrets(text, "test.js")
    rules = {s["rule"] for s in secrets}
    assert "aws_access_key" in rules
    assert "github_pat" in rules
    for s in secrets:
        assert "*" in s["match"] or len(s["match"]) < 8  # redacted


def test_secret_placeholder_filtered():
    text = 'api_key = "YOUR_API_KEY_HERE"; password="changeme"; token="xxxxxxxxxxxx"'
    secrets = jsanalysis.extract_secrets(text, "t.js")
    assert all("example" not in s["match"].lower() for s in secrets)


def test_jwt_and_private_key():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36"
    assert any(s["rule"] == "jwt" for s in jsanalysis.extract_secrets(f'token={jwt}', "t"))
    pk = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert any(s["rule"] == "private_key" for s in jsanalysis.extract_secrets(pk, "t"))


def test_endpoint_regex():
    import re
    text = 'fetch("/api/v1/users/profile"); url:"/admin/settings.json"'
    eps = [m.group(1) for m in jsanalysis.ENDPOINT_RE.finditer(text)]
    assert any("/api/v1/users" in e for e in eps)


def test_detect_tech_version_extraction():
    t = probe.detect_tech(200, {"server": "nginx/1.18.0", "x-powered-by": "PHP/8.2.4"}, [], "")
    by = {x["name"]: x for x in t}
    assert by["Nginx"]["version"] == "1.18.0"
    assert by["PHP"]["version"] == "8.2.4"
    assert by["Nginx"]["cpe"].endswith("1.18.0")


def test_detect_tech_version_from_generator():
    t = probe.detect_tech(200, {}, [], '<meta name="generator" content="WordPress 6.4.2">/wp-content/')
    wp = [x for x in t if x["name"] == "WordPress"][0]
    assert wp.get("version") == "6.4.2"
