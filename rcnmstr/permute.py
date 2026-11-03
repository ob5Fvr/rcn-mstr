"""Corpus-aware DNS name permutation generator (dnsgen/altdns-style, improved).

Pure and deterministic so it can be unit-tested. The engine feeds it the live-host corpus so
permutations are driven by the target's own naming conventions, not just a static wordlist.
"""
from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional, Set

DATA = os.path.join(os.path.dirname(__file__), "data")

ENV_WORDS = ["dev", "development", "stg", "stage", "staging", "qa", "uat", "test", "testing", "prod",
             "production", "preprod", "pre", "sandbox", "sbx", "demo", "poc", "beta", "alpha", "canary",
             "next", "new", "old", "legacy", "internal", "int", "intra", "corp", "private", "public",
             "api", "admin", "app", "web", "portal", "vpn", "mgmt", "secure", "edge", "origin", "backup",
             "v1", "v2", "v3", "us", "eu", "asia", "us-east", "us-west", "eu-west", "eu-central", "ap-south"]

_WORDS_CACHE: Optional[List[str]] = None


def base_words() -> List[str]:
    global _WORDS_CACHE
    if _WORDS_CACHE is None:
        words = list(ENV_WORDS)
        p = os.path.join(DATA, "permute_words.txt")
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if w and not w.startswith("#"):
                        words.append(w)
        _WORDS_CACHE = list(dict.fromkeys(words))
    return _WORDS_CACHE


def split_sub(host: str, root: str) -> Optional[List[str]]:
    """Return the subdomain label list to the left of root, or None if host==root/not under root."""
    if host == root or not host.endswith("." + root):
        return None
    return host[: -len(root) - 1].split(".")


def extract_corpus(hosts: Iterable[str], roots: Iterable[str], min_len: int = 3) -> Set[str]:
    """Harvest naming tokens from observed subdomains (split on '.' and '-')."""
    roots = sorted(roots, key=len, reverse=True)
    tokens: Set[str] = set()
    for h in hosts:
        root = next((r for r in roots if h == r or h.endswith("." + r)), None)
        if not root:
            continue
        labels = split_sub(h, root)
        if not labels:
            continue
        for lab in labels:
            for t in [lab] + lab.split("-"):
                if len(t) >= min_len and re.match(r"^[a-z0-9]+$", t):
                    tokens.add(t)
    return tokens


def _number_mods(sub: str, count: int = 3) -> Set[str]:
    out = set()
    for m in re.finditer(r"\d{1,4}", sub):
        d = m.group()
        n = int(d)
        for delta in range(1, count + 1):
            out.add(sub[:m.start()] + str(n + delta).zfill(len(d)) + sub[m.end():])
            if n - delta >= 0:
                out.add(sub[:m.start()] + str(n - delta).zfill(len(d)) + sub[m.end():])
    return out


def permute_host(host: str, root: str, words: List[str], num_count: int = 3) -> Set[str]:
    """Generate permutations of a single host under root using the supplied word set."""
    labels = split_sub(host, root)
    if labels is None:
        labels = []
    out: Set[str] = set()

    def emit(new_labels):
        if new_labels:
            name = ".".join(new_labels + [root])
            if len(name) <= 253 and all(0 < len(l) <= 63 for l in new_labels):
                out.add(name)

    # 1. insert each word at every index among the existing labels (prefix, middle, between)
    for w in words:
        for i in range(len(labels) + 1):
            emit(labels[:i] + [w] + labels[i:])

    if labels:
        first = labels[0]
        rest = labels[1:]
        # 2. join word to the first label with '-' on both sides, and concatenation
        for w in words:
            if w == first:
                continue
            emit([f"{w}-{first}"] + rest)
            emit([f"{first}-{w}"] + rest)
            emit([f"{w}{first}"] + rest)
            emit([f"{first}{w}"] + rest)
        # 3. word swap within dash-separated tokens of the first label
        toks = first.split("-")
        if len(toks) > 1:
            for i, t in enumerate(toks):
                for w in words:
                    if w != t:
                        nt = toks[:]
                        nt[i] = w
                        emit(["-".join(nt)] + rest)
        # 4. number increment/decrement anywhere in the subdomain
        sub = ".".join(labels)
        for mod in _number_mods(sub, num_count):
            emit(mod.split("."))

    out.discard(host)
    return out


def generate(hosts: List[str], roots: List[str], extra_words: Optional[Iterable[str]] = None,
             num_count: int = 3, cap: Optional[int] = None, use_corpus: bool = True) -> List[str]:
    """Generate a de-duplicated permutation candidate list for a set of hosts."""
    roots = sorted(roots, key=len, reverse=True)
    words = list(base_words())
    if use_corpus:
        words = list(dict.fromkeys(words + sorted(extract_corpus(hosts, roots))))
    if extra_words:
        words = list(dict.fromkeys(words + list(extra_words)))
    seen: Set[str] = set()
    out: List[str] = []
    for h in sorted(hosts, key=len):
        root = next((r for r in roots if h == r or h.endswith("." + r)), None)
        if not root:
            continue
        for cand in permute_host(h, root, words, num_count):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
                if cap and len(out) >= cap:
                    return out
    return out
