"""Classification + parser pipeline tests (PRD F2.1, F2.2, N2)."""

from __future__ import annotations

from packora.capture.base import Frame
from packora.models.packet import Classification
from packora.parsers import parse_frame

from conftest import (
    ACK,
    PSH,
    SYN,
    dns_query_payload,
    eth_header,
    frame,
    tcp_frame,
    udp_frame,
)


def test_parsed_tcp_packet_fields() -> None:
    pkt = parse_frame(tcp_frame(sport=40000, dport=80, seq=77, flags=SYN | ACK))
    assert pkt.classification is Classification.PARSED
    assert pkt.src_ip == "10.0.0.5"
    assert pkt.dst_ip == "10.0.0.1"
    assert (pkt.src_port, pkt.dst_port) == (40000, 80)
    assert pkt.tcp_flags is not None and pkt.tcp_flags.as_str() == "S,A"
    assert pkt.seq == 77
    assert pkt.proto_name == "TCP"
    summary = pkt.one_liner()
    assert "flags=S,A" in summary
    assert "10.0.0.5:40000 -> 10.0.0.1:80" in summary


def test_dns_query_classification() -> None:
    payload = dns_query_payload("example.test", response=False, answers=0)
    pkt = parse_frame(udp_frame(dport=53, sport=53000, payload=payload))
    assert pkt.classification is Classification.PARSED
    assert pkt.dns is not None
    assert pkt.dns.name == "example.test"
    assert pkt.dns.qtype == "A"
    assert pkt.dns.is_response is False
    assert pkt.proto_name == "DNS"
    assert "DNS query A example.test" in pkt.one_liner()


def test_dns_response_metadata() -> None:
    payload = dns_query_payload("example.test", response=True, answers=2)
    pkt = parse_frame(udp_frame(dport=53000, sport=53, payload=payload))
    assert pkt.dns is not None
    assert pkt.dns.is_response is True
    assert pkt.dns.answer_count == 2
    assert "DNS response: 2 answer(s)" in pkt.one_liner()


def test_http_request_extraction() -> None:
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"
    pkt = parse_frame(tcp_frame(dport=80, flags=PSH | ACK, payload=payload))
    assert pkt.http is not None
    assert pkt.http.kind == "request"
    assert pkt.http.method == "GET"
    assert pkt.http.path == "/index.html"
    assert pkt.http.host == "example.test"
    assert "HTTP GET /index.html (example.test)" in pkt.one_liner()


def test_http_response_extraction() -> None:
    payload = b"HTTP/1.0 200 OK\r\nServer: TestSrv\r\n\r\nbody"
    pkt = parse_frame(tcp_frame(dport=40000, sport=80, flags=PSH | ACK, payload=payload))
    assert pkt.http is not None
    assert pkt.http.kind == "response"
    assert pkt.http.status_code == 200
    assert "HTTP 200" in pkt.one_liner()


def test_https_payload_not_marked_http() -> None:
    pkt = parse_frame(tcp_frame(dport=443, flags=PSH | ACK, payload=b"\x16\x03\x01\x00\x05hello"))
    assert pkt.http is None
    assert pkt.classification is Classification.PARSED


def test_unsupported_ethertype_keeps_identifier() -> None:
    pkt = parse_frame(frame(ip_payload=b"whatever", ethertype=0x4321))
    assert pkt.classification is Classification.UNSUPPORTED
    assert pkt.unsupported_protocol is not None
    assert "0x4321" in pkt.unsupported_protocol
    assert pkt.malformed_reason is None


def test_ipv6_is_unsupported_not_malformed() -> None:
    pkt = parse_frame(frame(ip_payload=b"\x60" + b"\x00" * 19, ethertype=0x86DD))
    assert pkt.classification is Classification.UNSUPPORTED
    assert "IPv6" in (pkt.unsupported_protocol or "")


def test_vlan_is_unsupported() -> None:
    pkt = parse_frame(frame(b"x", ethertype=0x8100))
    assert pkt.classification is Classification.UNSUPPORTED
    assert "VLAN" in (pkt.unsupported_protocol or "")


def test_malformed_truncated_ethernet() -> None:
    pkt = parse_frame(Frame(ts=0.0, raw=bytes(10)))
    assert pkt.classification is Classification.MALFORMED
    assert "truncated ethernet header" in (pkt.malformed_reason or "")


def test_malformed_truncated_ipv4() -> None:
    pkt = parse_frame(Frame(ts=0.0, raw=eth_header() + b"\x45\x00\x00"))
    assert pkt.classification is Classification.MALFORMED
    assert pkt.malformed_reason is not None


def test_malformed_ipv4_declared_header_is_not_present() -> None:
    raw = bytearray(tcp_frame().raw[:34])
    raw[14] = 0x46  # IHL says 24 bytes, but only a 20-byte IPv4 header exists.
    pkt = parse_frame(Frame(ts=0.0, raw=bytes(raw)))
    assert pkt.classification is Classification.MALFORMED


def test_malformed_udp_declared_length_is_not_present() -> None:
    raw = bytearray(udp_frame(payload=b"x").raw)
    raw[38:40] = (100).to_bytes(2, "big")  # UDP length field, after Ethernet + IPv4 + ports
    pkt = parse_frame(Frame(ts=0.0, raw=bytes(raw)))
    assert pkt.classification is Classification.MALFORMED


def test_never_crashes_on_garbage() -> None:
    # Valid-looking ethernet header + garbage IP bytes -> malformed, never a crash.
    pkt = parse_frame(Frame(ts=0.0, raw=eth_header() + b"\xff" * 30))
    assert pkt.classification is Classification.MALFORMED
    assert not pkt.http and not pkt.dns

    # Fully-random frame -> unsupported/malformed, never an exception.
    from random import randbytes

    pkt2 = parse_frame(Frame(ts=0.0, raw=randbytes(60)))
    assert not pkt2.http and not pkt2.dns


def test_unsupported_ip_protocol_is_not_malformed() -> None:
    pkt = parse_frame(frame(ip_payload=b"\x08\x00\x00\x00\x00\x00frame-data", proto=1))
    assert pkt.classification is Classification.UNSUPPORTED
    assert pkt.ip_proto == 1
    assert "ICMP" in (pkt.unsupported_protocol or "")


def test_parsed_ack_payload_fields() -> None:
    pkt = parse_frame(tcp_frame(sport=80, dport=41000, flags=ACK))
    assert pkt.classification is Classification.PARSED
    assert pkt.tcp_flags is not None and pkt.tcp_flags.as_str() == "A"


def test_payload_preview_populated() -> None:
    pkt = parse_frame(tcp_frame(dport=443, flags=PSH | ACK, payload=b"\x16\x03\x01\x00\x05hello"))
    assert pkt.payload_preview
