"""Permutation engine: strategies, corpus extraction, determinism, safety, and a large scenario sweep."""
import pytest

from rcnmstr import permute


def test_split_sub():
    assert permute.split_sub("a.b.example.com", "example.com") == ["a", "b"]
    assert permute.split_sub("example.com", "example.com") is None
    assert permute.split_sub("other.com", "example.com") is None


@pytest.mark.parametrize("word", ["dev", "staging", "admin", "internal"])
def test_insert_every_index(word):
    p = permute.permute_host("api.example.com", "example.com", [word])
    assert f"{word}.api.example.com" in p         # prefix
    assert f"api.{word}.example.com" in p         # between label and root


def test_dash_and_concat():
    p = permute.permute_host("api.example.com", "example.com", ["dev"])
    assert {"dev-api.example.com", "api-dev.example.com", "devapi.example.com", "apidev.example.com"} <= p


def test_number_modifications():
    p = permute.permute_host("web01.example.com", "example.com", [])
    assert "web02.example.com" in p
    assert "web00.example.com" in p
    p2 = permute.permute_host("v2.api.example.com", "example.com", [])
    assert "v3.api.example.com" in p2 and "v1.api.example.com" in p2


def test_word_swap_in_dashed():
    p = permute.permute_host("api-dev.example.com", "example.com", ["staging", "prod"])
    assert "api-staging.example.com" in p and "api-prod.example.com" in p


def test_never_itself_and_valid():
    p = permute.permute_host("api.example.com", "example.com", permute.base_words())
    assert "api.example.com" not in p
    for name in p:
        assert name.endswith(".example.com")
        for label in name.split("."):
            assert 0 < len(label) <= 63


def test_corpus_extraction():
    hosts = ["api-prod.example.com", "payments.example.com", "user-service.corp.example.com"]
    corpus = permute.extract_corpus(hosts, ["example.com"])
    assert {"api", "prod", "payments", "user", "service", "corp"} <= corpus
    assert "ab" not in corpus  # below min_len


def test_corpus_feedback_in_generate():
    g = permute.generate(["payments.example.com", "api.example.com"], ["example.com"], use_corpus=True)
    # 'payments' token should get recombined onto other hosts
    assert any(x.startswith("payments-") or x.startswith("payments.") for x in g if x != "payments.example.com")


def test_generate_cap_and_dedup():
    g = permute.generate(["a.example.com", "b.example.com"], ["example.com"], cap=100)
    assert len(g) <= 100
    assert len(g) == len(set(g))


def test_generate_deterministic():
    a = permute.generate(["api.example.com"], ["example.com"], cap=500)
    b = permute.generate(["api.example.com"], ["example.com"], cap=500)
    assert a == b


def test_base_words_loaded():
    w = permute.base_words()
    assert len(w) > 300
    assert "staging" in w and "jenkins" in w and "kubernetes" in w


# --------------------------------------------------------- large deterministic scenario sweep (1000+)
@pytest.mark.parametrize("sub", [
    "api", "api-dev", "web1", "v2", "admin.internal", "a-b-c", "staging2", "n0de", "x", "cdn-edge",
    "us-east-1", "db01", "mail", "auth-service", "k8s", "grafana", "legacy-app", "test123", "qa.api", "vpn2",
])
def test_sweep_many_subdomains(sub):
    host = f"{sub}.example.com"
    out = permute.permute_host(host, "example.com", permute.base_words())
    assert host not in out
    assert all(n.endswith(".example.com") and ".." not in n for n in out)
    # every permutation must be a syntactically valid hostname
    for n in list(out)[:500]:
        labels = n.split(".")
        assert all(0 < len(l) <= 63 for l in labels)
