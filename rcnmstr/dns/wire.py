"""Minimal, dependency-free DNS wire format encoder/decoder (RFC 1035 + EDNS0)."""
from __future__ import annotations

import ipaddress
import os
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "OPT": 41, "DS": 43, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48,
    "NSEC3": 50, "NSEC3PARAM": 51, "TLSA": 52, "CAA": 257, "AXFR": 252, "ANY": 255,
}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
          5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
          16: "BADVERS", 17: "BADKEY", 18: "BADTIME", 19: "BADMODE", 20: "BADNAME", 21: "BADALG",
          22: "BADTRUNC", 23: "BADCOOKIE"}

EDNS_PAYLOAD = 1232
MAX_POINTER_JUMPS = 64


class DNSParseError(Exception):
    pass


def qtype_num(qtype) -> int:
    if isinstance(qtype, int):
        return qtype
    q = qtype.upper()
    if q in QTYPES:
        return QTYPES[q]
    if q.startswith("TYPE") and q[4:].isdigit():
        return int(q[4:])
    raise ValueError(f"unknown qtype {qtype}")


def qtype_name(num: int) -> str:
    return QTYPE_NAMES.get(num, f"TYPE{num}")


def normalize(name: str) -> str:
    return name.strip().rstrip(".").lower()


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid label in {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > 255:
        raise ValueError("name too long")
    return bytes(out)


def build_query(name: str, qtype="A", tid: Optional[int] = None, rd: bool = True,
                edns: bool = True, payload: int = EDNS_PAYLOAD) -> Tuple[int, bytes]:
    if tid is None:
        tid = struct.unpack(">H", os.urandom(2))[0]
    flags = 0x0100 if rd else 0x0000
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 1 if edns else 0)
    q = encode_name(name) + struct.pack(">HH", qtype_num(qtype), 1)
    opt = b""
    if edns:
        # root name, TYPE=OPT, CLASS=udp payload, TTL=ext-rcode/version/flags, RDLEN=0
        opt = b"\x00" + struct.pack(">HHIH", 41, payload, 0, 0)
    return tid, header + q + opt


def read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, offset after name in original stream)."""
    labels: List[str] = []
    jumps = 0
    end_offset = None
    visited = set()
    n = len(data)
    while True:
        if offset >= n:
            raise DNSParseError("name runs past end of packet")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= n:
                raise DNSParseError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if end_offset is None:
                end_offset = offset + 2
            if ptr in visited or ptr >= n:
                raise DNSParseError("compression loop / bad pointer")
            visited.add(ptr)
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise DNSParseError("too many compression pointers")
            offset = ptr
            continue
        if length & 0xC0:
            raise DNSParseError("unsupported label type")
        offset += 1
        if length == 0:
            break
        if offset + length > n:
            raise DNSParseError("label runs past end")
        labels.append(data[offset:offset + length].decode("latin-1"))
        offset += length
        if sum(len(x) + 1 for x in labels) > 255:
            raise DNSParseError("name too long")
    if end_offset is None:
        end_offset = offset
    return ".".join(labels).lower(), end_offset


@dataclass
class RR:
    name: str
    type: str
    ttl: int
    data: object
    cls: int = 1

    def to_dict(self):
        return {"name": self.name, "type": self.type, "ttl": self.ttl, "data": self.data}


@dataclass
class Message:
    id: int
    flags: int
    rcode: str
    question: List[Tuple[str, int]] = field(default_factory=list)
    answers: List[RR] = field(default_factory=list)
    authority: List[RR] = field(default_factory=list)
    additional: List[RR] = field(default_factory=list)

    @property
    def tc(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def aa(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def qr(self) -> bool:
        return bool(self.flags & 0x8000)

    def records(self, rtype: str) -> List[RR]:
        return [r for r in self.answers if r.type == rtype]


def _parse_rdata(data: bytes, off: int, rdlen: int, rtype: int):
    end = off + rdlen
    if end > len(data):
        raise DNSParseError("rdata runs past end")
    rd = data[off:end]
    if rtype == 1:
        if rdlen != 4:
            raise DNSParseError("bad A rdlen")
        return str(ipaddress.IPv4Address(rd))
    if rtype == 28:
        if rdlen != 16:
            raise DNSParseError("bad AAAA rdlen")
        return str(ipaddress.IPv6Address(rd))
    if rtype in (2, 5, 12):
        return read_name(data, off)[0]
    if rtype == 15:
        pref = struct.unpack(">H", data[off:off + 2])[0]
        return {"preference": pref, "exchange": read_name(data, off + 2)[0]}
    if rtype == 16:
        parts, i = [], 0
        while i < rdlen:
            ln = rd[i]
            parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
            i += 1 + ln
        return "".join(parts)
    if rtype == 6:
        mname, o = read_name(data, off)
        rname, o = read_name(data, o)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[o:o + 20])
        return {"mname": mname, "rname": rname, "serial": serial, "refresh": refresh,
                "retry": retry, "expire": expire, "minimum": minimum}
    if rtype == 33:
        prio, weight, port = struct.unpack(">HHH", data[off:off + 6])
        return {"priority": prio, "weight": weight, "port": port, "target": read_name(data, off + 6)[0]}
    if rtype == 257:
        flags, tlen = rd[0], rd[1]
        return {"flags": flags, "tag": rd[2:2 + tlen].decode("latin-1"),
                "value": rd[2 + tlen:].decode("utf-8", "replace")}
    if rtype == 47:  # NSEC: next owner name + type bitmap
        next_name, o = read_name(data, off)
        return {"next": next_name, "types": _type_bitmap(data[o:end])}
    if rtype == 50:  # NSEC3: hash alg, flags, iterations, salt, next hashed owner, type bitmap
        alg, flags3, iterations = rd[0], rd[1], struct.unpack(">H", rd[2:4])[0]
        salt_len = rd[4]
        salt = rd[5:5 + salt_len]
        o = 5 + salt_len
        hlen = rd[o]
        o += 1
        next_hashed = rd[o:o + hlen]
        return {"algorithm": alg, "flags": flags3, "iterations": iterations, "salt": salt.hex(),
                "next_hashed": _b32hex(next_hashed), "types": _type_bitmap(rd[o + hlen:])}
    if rtype == 51:  # NSEC3PARAM
        salt_len = rd[4]
        return {"algorithm": rd[0], "flags": rd[1], "iterations": struct.unpack(">H", rd[2:4])[0],
                "salt": rd[5:5 + salt_len].hex()}
    return rd.hex()


def _type_bitmap(rd: bytes) -> list:
    """Decode an NSEC/NSEC3 type-bitmap into a list of record-type names."""
    out, i = [], 0
    while i + 2 <= len(rd):
        window, blen = rd[i], rd[i + 1]
        block = rd[i + 2:i + 2 + blen]
        for bi, byte in enumerate(block):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    t = window * 256 + bi * 8 + bit
                    out.append(qtype_name(t))
        i += 2 + blen
    return out


_B32HEX = "0123456789abcdefghijklmnopqrstuv"


def _b32hex(data: bytes) -> str:
    """RFC4648 base32hex (lowercase, no padding) - the encoding NSEC3 owner hashes use."""
    bits, out = 0, []
    val = 0
    for b in data:
        val = (val << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_B32HEX[(val >> bits) & 0x1F])
    if bits:
        out.append(_B32HEX[(val << (5 - bits)) & 0x1F])
    return "".join(out)


def _parse_rr(data: bytes, off: int) -> Tuple[RR, int]:
    name, off = read_name(data, off)
    if off + 10 > len(data):
        raise DNSParseError("truncated RR header")
    rtype, cls, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
    off += 10
    rdata = None if rtype == 41 else _parse_rdata(data, off, rdlen, rtype)
    return RR(name, qtype_name(rtype), ttl, rdata, cls), off + rdlen


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise DNSParseError("packet shorter than header")
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    ext_rcode = 0
    off = 12
    questions = []
    for _ in range(qd):
        name, off = read_name(data, off)
        if off + 4 > len(data):
            raise DNSParseError("truncated question")
        qt, _qc = struct.unpack(">HH", data[off:off + 4])
        off += 4
        questions.append((name, qt))
    sections = []
    for count in (an, ns, ar):
        recs = []
        for _ in range(count):
            try:
                rr, off = _parse_rr(data, off)
            except DNSParseError:
                if flags & 0x0200:  # truncated message, keep what we have
                    break
                raise
            if rr.type == "OPT":
                ext_rcode = (rr.ttl >> 24) & 0xFF
                continue
            recs.append(rr)
        sections.append(recs)
    rcode_num = (ext_rcode << 4) | (flags & 0x000F)
    return Message(tid, flags, RCODES.get(rcode_num, f"RCODE{rcode_num}"), questions, *sections)


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


# ---------------------------------------------------------------- server side helpers (used by tests / fake servers)
def encode_rr(name: str, rtype: str, data, ttl: int = 60) -> bytes:
    t = qtype_num(rtype)
    if t == 1:
        rd = ipaddress.IPv4Address(data).packed
    elif t == 28:
        rd = ipaddress.IPv6Address(data).packed
    elif t in (2, 5, 12):
        rd = encode_name(data)
    elif t == 15:
        rd = struct.pack(">H", data["preference"]) + encode_name(data["exchange"])
    elif t == 16:
        raw = data.encode()
        rd = b"".join(bytes([len(raw[i:i + 255])]) + raw[i:i + 255] for i in range(0, max(len(raw), 1), 255))
    elif t == 6:
        rd = encode_name(data["mname"]) + encode_name(data["rname"]) + struct.pack(
            ">IIIII", data.get("serial", 1), data.get("refresh", 3600), data.get("retry", 600),
            data.get("expire", 86400), data.get("minimum", 60))
    elif t == 33:
        rd = struct.pack(">HHH", data["priority"], data["weight"], data["port"]) + encode_name(data["target"])
    elif t == 257:
        tag = data["tag"].encode()
        rd = bytes([data.get("flags", 0), len(tag)]) + tag + data["value"].encode()
    elif t == 47:  # NSEC
        rd = encode_name(data["next"]) + encode_type_bitmap(data.get("types", ["A", "RRSIG", "NSEC"]))
    else:
        rd = bytes.fromhex(data)
    return encode_name(name) + struct.pack(">HHIH", t, 1, ttl, len(rd)) + rd


def encode_type_bitmap(types) -> bytes:
    nums = sorted(qtype_num(t) for t in types)
    windows: dict = {}
    for n in nums:
        w, bit = n // 256, n % 256
        windows.setdefault(w, bytearray())
        idx = bit // 8
        while len(windows[w]) <= idx:
            windows[w].append(0)
        windows[w][idx] |= 0x80 >> (bit % 8)
    out = b""
    for w in sorted(windows):
        out += bytes([w, len(windows[w])]) + bytes(windows[w])
    return out


def build_response(query: bytes, rcode: int = 0, answers=(), authority=(), aa: bool = True,
                   tc: bool = False) -> bytes:
    tid = struct.unpack(">H", query[:2])[0]
    qflags = struct.unpack(">H", query[2:4])[0]
    _, qend = read_name(query, 12)
    question = query[12:qend + 4]
    flags = 0x8000 | (qflags & 0x0100) | 0x0080 | (0x0400 if aa else 0) | (0x0200 if tc else 0) | (rcode & 0xF)
    body = b"".join(answers) + b"".join(authority)
    return struct.pack(">HHHHHH", tid, flags, 1, len(answers), len(authority), 0) + question + body
