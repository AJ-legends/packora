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
    ipv4_header,
    tcp_frame,
    tcp_header,
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


def test_truncated_ipv6_is_malformed() -> None:
    pkt = parse_frame(frame(ip_payload=b"\x60" + b"\x00" * 19, ethertype=0x86DD))
    assert pkt.classification is Classification.MALFORMED
    assert "IPv6" in (pkt.malformed_reason or "")


def test_truncated_vlan_header_is_malformed() -> None:
    pkt = parse_frame(frame(b"x", ethertype=0x8100))
    assert pkt.classification is Classification.MALFORMED
    assert "ethernet" in (pkt.malformed_reason or "")


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


def test_icmp_is_parsed_not_malformed() -> None:
    pkt = parse_frame(frame(ip_payload=b"\x08\x00\x00\x00\x00\x00frame-data", proto=1))
    assert pkt.classification is Classification.PARSED
    assert pkt.ip_proto == 1
    assert pkt.proto_name == "ICMP"
    assert any("echo_request" in note for note in pkt.notes)


def test_arp_is_parsed() -> None:
    arp = (
        b"\x00\x01\x08\x00\x06\x04\x00\x01"
        + bytes.fromhex("020000000001")
        + bytes([10, 0, 0, 5])
        + bytes(6)
        + bytes([10, 0, 0, 1])
    )
    pkt = parse_frame(Frame(ts=1.0, raw=eth_header(ethertype=0x0806) + arp))
    assert pkt.classification is Classification.PARSED
    assert pkt.proto_name == "ARP"
    assert pkt.arp_sender_ip == "10.0.0.5"


def test_vlan_wrapped_ipv4_is_parsed() -> None:
    tcp = tcp_header(40000, 80, 1)
    vlan = (7).to_bytes(2, "big") + (0x0800).to_bytes(2, "big")
    raw = eth_header(ethertype=0x8100) + vlan + ipv4_header(tcp) + tcp
    pkt = parse_frame(Frame(ts=1.0, raw=raw))
    assert pkt.classification is Classification.PARSED
    assert pkt.proto_name == "TCP"
    assert "VLAN 7" in pkt.notes


def test_raw_ip_linktype_is_parsed_without_ethernet_header() -> None:
    tcp = tcp_header(40000, 80, 1)
    raw = ipv4_header(tcp) + tcp
    pkt = parse_frame(Frame(ts=1.0, raw=raw, linktype=12))
    assert pkt.classification is Classification.PARSED
    assert pkt.proto_name == "TCP"
    assert pkt.src_ip == "10.0.0.5"


def test_ipv6_icmpv6_is_parsed() -> None:
    payload = b"\x80\x00\x00\x00"  # echo request + unused checksum
    header = bytes([0x60, 0, 0, 0]) + len(payload).to_bytes(2, "big") + bytes([58, 64])
    header += bytes.fromhex("20010db8000000000000000000000001")
    header += bytes.fromhex("20010db8000000000000000000000002")
    pkt = parse_frame(Frame(ts=1.0, raw=eth_header(ethertype=0x86DD) + header + payload))
    assert pkt.classification is Classification.PARSED
    assert pkt.proto_name == "ICMPv6"


def test_ntp_is_parsed() -> None:
    ntp_payload = bytes([0x23, 2]) + bytes(46)  # v4 client, stratum 2
    pkt = parse_frame(udp_frame(sport=123, dport=50000, payload=ntp_payload))
    assert pkt.ntp is not None
    assert pkt.ntp.mode == "client"
    assert pkt.proto_name == "NTP"


def test_dhcp_options_are_parsed_and_truncation_is_safe() -> None:
    dhcp = bytes(236) + b"\x63\x82\x53\x63" + b"\x35\x01\x01\x0c\x04test\xff"
    pkt = parse_frame(udp_frame(sport=68, dport=67, payload=dhcp))
    assert pkt.dhcp is not None
    assert pkt.dhcp.message_type == "discover"
    assert pkt.dhcp.hostname == "test"
    malformed = parse_frame(udp_frame(sport=68, dport=67, payload=dhcp[:-1] + b"\x0c\x08x"))
    assert "malformed DHCP options" in malformed.notes


def test_tls_client_hello_metadata_is_parsed() -> None:
    server_name = b"example.test"
    extension = b"\x00\x00" + (5 + len(server_name)).to_bytes(2, "big")
    extension += (3 + len(server_name)).to_bytes(2, "big") + b"\x00" + len(server_name).to_bytes(2, "big") + server_name
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += len(extension).to_bytes(2, "big") + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    tls_record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    pkt = parse_frame(tcp_frame(dport=443, flags=PSH | ACK, payload=tls_record))
    assert pkt.tls is not None
    assert pkt.tls.server_name == "example.test"
    assert pkt.proto_name == "TLS"


def test_truncated_tcp_options_are_malformed() -> None:
    raw = bytearray(tcp_frame().raw)
    raw[46] = 0x60  # TCP data offset says 24 bytes while only 20 are present.
    pkt = parse_frame(Frame(ts=1.0, raw=bytes(raw)))
    assert pkt.classification is Classification.MALFORMED


def test_parsed_ack_payload_fields() -> None:
    pkt = parse_frame(tcp_frame(sport=80, dport=41000, flags=ACK))
    assert pkt.classification is Classification.PARSED
    assert pkt.tcp_flags is not None and pkt.tcp_flags.as_str() == "A"


def test_payload_preview_populated() -> None:
    pkt = parse_frame(tcp_frame(dport=443, flags=PSH | ACK, payload=b"\x16\x03\x01\x00\x05hello"))
    assert pkt.payload_preview
