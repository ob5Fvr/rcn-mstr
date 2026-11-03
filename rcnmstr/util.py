"""Small shared helpers: hashing (simhash, murmur3), entropy, redaction, html helpers, ip helpers."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import re
import time
from collections import Counter
from typing import Iterable, List, Optional

# ----------------------------------------------------------------------------- hashing


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32, signed result (same as python mmh3.hash)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    nblocks = length // 4
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(content: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3(base64.encodebytes(content))."""
    return murmur3_32(base64.encodebytes(content))


_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


def simhash(text: str, bits: int = 64) -> int:
    tokens = _TOKEN_RE.findall(text.lower())
    if not tokens:
        return 0
    shingles = Counter(" ".join(tokens[i:i + 3]) for i in range(max(1, len(tokens) - 2)))
    v = [0] * bits
    for sh, w in shingles.items():
        h = int.from_bytes(hashlib.md5(sh.encode()).digest()[:8], "big")
        for i in range(bits):
            v[i] += w if (h >> i) & 1 else -w
    out = 0
    for i in range(bits):
        if v[i] > 0:
            out |= 1 << i
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def similar(a_hash: int, b_hash: int, threshold: int = 6) -> bool:
    return hamming(a_hash, b_hash) <= threshold


# ----------------------------------------------------------------------------- strings


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2 + 2:
        return value[:2] + "*" * max(0, len(value) - 2)
    return value[:keep] + "*" * min(len(value) - keep * 2, 24) + value[-keep:]


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def html_title(body: str) -> str:
    m = _TITLE_RE.search(body[:200000])
    if not m:
        return ""
    import html
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:300]


def now() -> float:
    return time.time()


def iso(ts: Optional[float] = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts or time.time()))


# ----------------------------------------------------------------------------- ip helpers


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_global


def is_private_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_private and not ip.is_loopback


def expand_cidr(cidr: str, max_hosts: int = 256) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.num_addresses > max_hosts:
        return []
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(h) for h in net.hosts()]


def uniq(seq: Iterable) -> list:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def chunks(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]
