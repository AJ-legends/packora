"""Packora protocol parsers.

`parse_frame` (below) is the root entry: Frame -> PacketInfo under the
classification contract (PRD F2.1).
"""

from __future__ import annotations

from packora.capture.base import Frame
from packora.models.packet import Classification, PacketInfo
from packora.parsers import dns as dns_parser
from packora.parsers import ethernet as eth_parser
from packora.parsers import http as http_parser
from packora.parsers import ip as ip_parser
from packora.parsers import transport as tp_parser

__all__ = ["parse_frame"]

DNS_PORT = 53
HTTP_PORTS = (80, 8080)


def _hex_preview(raw: bytes) -> str:
    return raw[:16].hex(" ")


def parse_frame(frame: Frame) -> PacketInfo:
    def broken(reason: str) -> PacketInfo:
        return PacketInfo(
            ts=frame.ts,
            wire_len=len(frame.raw),
            classification=Classification.MALFORMED,
            malformed_reason=reason,
            payload_preview=_hex_preview(frame.raw),
        )

    try:
        eth = eth_parser.parse(frame.raw)
    except Exception:  # noqa: BLE001 - defensive by design (PRD N2)
        return broken("ethernet decode failed")
    if eth is None:
        return broken("truncated ethernet header (<14 bytes)")

    if eth.ethertype != eth_parser.ETHERTYPE_IP:
        return PacketInfo(
            ts=frame.ts,
            wire_len=len(frame.raw),
            classification=Classification.UNSUPPORTED,
            src_mac=eth.src_mac,
            dst_mac=eth.dst_mac,
            ethertype=eth.ethertype,
            unsupported_protocol=eth_parser.ethertype_note(eth.ethertype),
            payload_preview=_hex_preview(eth.payload),
        )

    try:
        ip = ip_parser.parse(eth.payload)
    except Exception:  # noqa: BLE001
        return broken("IPv4 decode failed")
    if ip is None:
        version = eth.payload[0] >> 4 if eth.payload else 0
        if version != 4:
            return broken(f"unexpected IP version {version}")
        return broken("truncated or short IPv4 header")

    proto_name = ip_parser.IPPROTO_NAMES.get(ip.proto, f"proto {ip.proto}")
    pkt = PacketInfo(
        ts=frame.ts,
        wire_len=len(frame.raw),
        classification=Classification.PARSED,
        src_mac=eth.src_mac,
        dst_mac=eth.dst_mac,
        ethertype=eth.ethertype,
        src_ip=ip.src_ip,
        dst_ip=ip.dst_ip,
        ip_proto=ip.proto,
        proto_name=proto_name,
    )
    if ip.proto == ip_parser.IPPROTO_TCP:
        _decode_tcp(pkt, ip.payload)
    elif ip.proto == ip_parser.IPPROTO_UDP:
        _decode_udp(pkt, ip.payload)
    else:
        pkt.classification = Classification.UNSUPPORTED
        pkt.unsupported_protocol = ip_parser.IPPROTO_OUT_OF_SCOPE.get(
            ip.proto, f"unsupported IPv4 protocol {ip.proto}"
        )
        pkt.payload_preview = _hex_preview(ip.payload)
    return pkt


def _decode_tcp(pkt: PacketInfo, payload: bytes) -> None:
    seg = tp_parser.parse_tcp(payload)
    if seg is None:
        pkt.classification = Classification.MALFORMED
        pkt.malformed_reason = "truncated or short TCP header"
        return
    pkt.src_port = seg.sport
    pkt.dst_port = seg.dport
    pkt.tcp_flags = seg.flags
    pkt.seq = seg.seq
    pkt.payload_len = len(seg.payload)
    pkt.app_payload = seg.payload
    pkt.payload_preview = _hex_preview(seg.payload)
    decode = None
    if seg.payload and (pkt.dst_port in HTTP_PORTS or pkt.src_port in HTTP_PORTS):
        decode = http_parser.parse(seg.payload)
        pkt.http = decode.info
        if decode.info is None and decode.failed:
            pkt.notes.append("HTTP-like payload did not decode")
    if pkt.dst_port == DNS_PORT or pkt.src_port == DNS_PORT:
        # DNS over TCP carries a 2-byte length prefix before the message; stream
        # framing is out of scope for v1, so report a note instead of a bad decode.
        pkt.proto_name = "DNS/TCP"
        pkt.notes.append("DNS over TCP stream decode is out of scope for v1")


def _decode_udp(pkt: PacketInfo, payload: bytes) -> None:
    dgram = tp_parser.parse_udp(payload)
    if dgram is None:
        pkt.classification = Classification.MALFORMED
        pkt.malformed_reason = "truncated or short UDP header"
        return
    pkt.src_port = dgram.sport
    pkt.dst_port = dgram.dport
    pkt.payload_len = len(dgram.payload)
    pkt.app_payload = dgram.payload
    pkt.payload_preview = _hex_preview(dgram.payload)
    if pkt.dst_port in HTTP_PORTS or pkt.src_port in HTTP_PORTS:
        pkt.proto_name = "HTTP/UDP"
        pkt.notes.append("non-TCP traffic on an HTTP port (no HTTP decode)")
    if pkt.dst_port == DNS_PORT or pkt.src_port == DNS_PORT:
        decode = dns_parser.parse(dgram.payload)
        if decode.info is None:
            pkt.notes.append("DNS decode failed (kept as transport-only UDP)")
            return
        pkt.dns = decode.info
        pkt.proto_name = "DNS"
