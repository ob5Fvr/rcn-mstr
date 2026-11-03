"""Scope handling, host cleaning, registrable-domain extraction, and util hashing/entropy."""
import pytest

from rcnmstr import util
from rcnmstr.scope import Scope, clean_host, registrable


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://www.example.com/path?x=1", "www.example.com"),
    ("http://user:pass@api.example.com:8443/x", "api.example.com"),
    ("*.example.com", "example.com"),
    ("  sub.example.com.  ", "sub.example.com"),
    ("javascript:alert(1)", None),
    ("not a host", None),
    ("1.2.3.4", None),          # bare IP is not a hostname
    ("a..b.com", None),
    ("xn--d1acufc.xn--p1ai", "xn--d1acufc.xn--p1ai"),
    ("foo_bar.example.com", "foo_bar.example.com"),
])
def test_clean_host(raw, expected):
    assert clean_host(raw) == expected


@pytest.mark.parametrize("host,reg", [
    ("www.example.com", "example.com"),
    ("a.b.c.example.co.uk", "example.co.uk"),
    ("x.github.io", "x.github.io"),
    ("deep.sub.example.com.au", "example.com.au"),
    ("example.com", "example.com"),
    ("a.b.example.org", "example.org"),
])
def test_registrable(host, reg):
    assert registrable(host) == reg


def test_scope_in_scope_and_exclude():
    s = Scope(["example.com"], include=["*.corp.example.net"], exclude=["secret.example.com", "*.vendor.example.com"])
    assert s.in_scope("a.example.com")
    assert s.in_scope("example.com")
    assert not s.in_scope("evil.com")
    assert not s.in_scope("secret.example.com")
    assert not s.in_scope("x.vendor.example.com")
    assert s.in_scope("a.corp.example.net")
    assert not s.in_scope("corp.example.org")


def test_scope_root_of_longest_match():
    s = Scope(["example.com", "sub.example.com"])
    assert s.root_of("a.sub.example.com") == "sub.example.com"
    assert s.root_of("a.example.com") == "example.com"
    assert s.root_of("other.com") is None


def test_scope_extract_hosts():
    s = Scope(["example.com"])
    text = "visit https://api.example.com and mail@mx.example.com or evil.com, also sub.api.example.com."
    hosts = s.extract_hosts(text)
    assert "api.example.com" in hosts
    assert "mx.example.com" in hosts
    assert "sub.api.example.com" in hosts
    assert "evil.com" not in hosts


def test_scope_keywords():
    s = Scope(["acme-corp.co.uk", "example.com"])
    kws = s.keywords()
    assert "acme-corp" in kws and "example" in kws


def test_scope_ip_cidr():
    s = Scope(["example.com"], include=["10.0.0.0/24"])
    assert s.ip_in_scope("10.0.0.5")
    assert not s.ip_in_scope("10.0.1.5")


def test_scope_from_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n*.api.example.com\n!secret.example.com\n# comment\n")
    s = Scope.from_file(["example.com"], str(f))
    assert "api.example.com" in s.roots or s.in_scope("x.api.example.com")
    assert not s.in_scope("secret.example.com")


# --------------------------------------------------------------------- util
def test_mmh3_known_vectors():
    # mmh3.hash(b"") == 0 ; mmh3.hash(b"hello") == 613153351
    assert util.murmur3_32(b"") == 0
    assert util.murmur3_32(b"hello") == 613153351
    assert util.murmur3_32(b"The quick brown fox") == util.murmur3_32(b"The quick brown fox")


def test_favicon_hash_stable():
    data = b"\x89PNG\r\n" + b"icon-bytes" * 20
    h = util.favicon_hash(data)
    assert isinstance(h, int)
    assert util.favicon_hash(data) == h


def test_simhash_similarity():
    a = util.simhash("the quick brown fox jumps over the lazy dog many times here")
    b = util.simhash("the quick brown fox jumps over the lazy dog many times here now")
    c = util.simhash("completely different content about databases and networking protocols entirely")
    assert util.hamming(a, b) < util.hamming(a, c)
    assert util.similar(a, b, threshold=12)


def test_entropy():
    assert util.shannon_entropy("aaaaaaaa") < 1.0
    assert util.shannon_entropy("aB3$xK9mZq2wL7") > 3.0


def test_redact():
    assert util.redact("AKIAIOSFODNN7EXAMPLE").startswith("AKIA")
    assert "*" in util.redact("AKIAIOSFODNN7EXAMPLE")
    assert util.redact("short") != "short" or len(util.redact("short")) == len("short")


def test_html_title():
    assert util.html_title("<html><head><title> Hello &amp; World </title></head>") == "Hello & World"
    assert util.html_title("<html>no title</html>") == ""


@pytest.mark.parametrize("ip,pub", [("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False),
                                     ("172.16.5.5", False), ("1.1.1.1", True), ("not-ip", False)])
def test_is_public_ip(ip, pub):
    assert util.is_public_ip(ip) == pub


def test_expand_cidr():
    assert util.expand_cidr("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert util.expand_cidr("10.0.0.0/8") == []  # too big
    assert util.expand_cidr("1.2.3.4/32") == ["1.2.3.4"]
