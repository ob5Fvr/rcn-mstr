"""DNS wire codec: encode/decode round trips, compression, EDNS, malformed packets, loop protection."""
import struct

import pytest

from rcnmstr.dns import wire


def test_encode_name_basic():
    assert wire.encode_name("a.com") == b"\x01a\x03com\x00"
    assert wire.encode_name("") == b"\x00"
    assert wire.encode_name("example.com.") == b"\x07example\x03com\x00"


def test_encode_name_invalid():
    with pytest.raises(ValueError):
        wire.encode_name("x" * 64 + ".com")
    with pytest.raises(ValueError):
        wire.encode_name(("a." * 130) + "com")


def test_build_query_has_edns():
    tid, pkt = wire.build_query("example.com", "A")
    assert pkt[:2] == struct.pack(">H", tid)
    assert struct.unpack(">H", pkt[10:12])[0] == 1  # arcount (OPT)
    assert b"\x00\x00)" in pkt  # OPT RR: root name + type 41


def test_qtype_helpers():
    assert wire.qtype_num("AAAA") == 28
    assert wire.qtype_num(5) == 5
    assert wire.qtype_num("TYPE99") == 99
    assert wire.qtype_name(257) == "CAA"
    assert wire.qtype_name(99999).startswith("TYPE")


def _hdr(tid, flags, qd=1, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", tid, flags, qd, an, ns, ar)


def test_parse_a_record():
    q = _hdr(0x1234, 0x8180, an=1) + wire.encode_name("example.com") + struct.pack(">HH", 1, 1)
    q += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
    msg = wire.parse_message(q)
    assert msg.rcode == "NOERROR"
    assert msg.records("A")[0].data == "93.184.216.34"
    assert msg.records("A")[0].ttl == 300


def test_parse_cname_and_compression():
    body = _hdr(1, 0x8180, an=2)
    body += wire.encode_name("www.example.com") + struct.pack(">HH", 1, 1)
    # CNAME www -> example.com (compression pointer to offset 16 = start of example.com label)
    name_off = 12
    target = b"\x03www\x07example\x03com\x00"
    cname_rd = b"\xc0" + bytes([name_off + 4])  # points to "example.com" within the question
    body += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(cname_rd)) + cname_rd
    body += b"\xc0" + bytes([name_off + 4]) + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    msg = wire.parse_message(body)
    assert msg.records("CNAME")[0].data == "example.com"
    assert msg.records("A")[0].data == "1.2.3.4"


def test_parse_mx_txt_soa():
    for rtype, data in [("MX", {"preference": 10, "exchange": "mail.example.com"}),
                        ("TXT", "v=spf1 include:_spf.google.com ~all"),
                        ("SOA", {"mname": "ns1.example.com", "rname": "hostmaster.example.com",
                                 "serial": 1, "refresh": 2, "retry": 3, "expire": 4, "minimum": 5})]:
        q = wire.build_query("example.com", rtype)[1]
        resp = wire.build_response(q[:-11], answers=[wire.encode_rr("example.com", rtype, data)])
        msg = wire.parse_message(resp)
        got = msg.records(rtype)[0].data
        if rtype == "MX":
            assert got["exchange"] == "mail.example.com" and got["preference"] == 10
        elif rtype == "TXT":
            assert "spf1" in got
        else:
            assert got["mname"] == "ns1.example.com" and got["minimum"] == 5


def test_parse_caa_srv_aaaa():
    q = wire.build_query("example.com", "A")[1][:-11]
    rrs = [wire.encode_rr("example.com", "AAAA", "2606:2800:220:1:248:1893:25c8:1946"),
           wire.encode_rr("example.com", "CAA", {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}),
           wire.encode_rr("_sip._tcp.example.com", "SRV",
                          {"priority": 1, "weight": 5, "port": 5060, "target": "sip.example.com"})]
    msg = wire.parse_message(wire.build_response(q, answers=rrs))
    assert msg.records("AAAA")[0].data.startswith("2606:")
    assert msg.records("CAA")[0].data["value"] == "letsencrypt.org"
    assert msg.records("SRV")[0].data["port"] == 5060


def test_nxdomain_rcode():
    q = wire.build_query("nope.example.com", "A")[1][:-11]
    msg = wire.parse_message(wire.build_response(q, rcode=3))
    assert msg.rcode == "NXDOMAIN"


def test_compression_loop_protection():
    # a pointer that points to itself -> must raise, not hang
    pkt = _hdr(1, 0x8180, an=1) + wire.encode_name("a.com") + struct.pack(">HH", 1, 1)
    loop_off = len(pkt)
    pkt += b"\xc0" + bytes([loop_off & 0xFF])  # name = pointer to itself
    pkt += struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    with pytest.raises(wire.DNSParseError):
        wire.parse_message(pkt)


def test_truncated_packet():
    with pytest.raises(wire.DNSParseError):
        wire.parse_message(b"\x00\x00")


def test_reverse_name():
    assert wire.reverse_name("1.2.3.4") == "4.3.2.1.in-addr.arpa"
    assert wire.reverse_name("::1").endswith("ip6.arpa")


def test_edns_ext_rcode():
    # OPT RR with ext-rcode high byte set -> combined rcode
    q = wire.build_query("example.com", "A")[1][:-11]
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0x01000000, 0)  # ext-rcode=1 -> +16
    resp = struct.pack(">HHHHHH", 1, 0x8180 | 6, 1, 0, 0, 1) + q[12:] + opt
    msg = wire.parse_message(resp)
    # ext-rcode high byte 1 -> (1<<4)|6 = 22 = BADTRUNC
    assert msg.rcode == "BADTRUNC"
