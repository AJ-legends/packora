"""Packora protocol parsers.

`parse_frame` (below) is the root entry: Frame -> PacketInfo under the
classification contract (PRD F2.1).
"""

from __future__ import annotations

from packora.capture.base import Frame
from packora.models.packet import Classification, PacketInfo
from packora.parsers import arp as arp_parser
from packora.parsers import dhcp as dhcp_parser
from packora.parsers import dns as dns_parser
from packora.parsers import ethernet as eth_parser
from packora.parsers import http as http_parser
from packora.parsers import icmp as icmp_parser
from packora.parsers import ip as ip_parser
from packora.parsers import ipv6 as ipv6_parser
from packora.parsers import ntp as ntp_parser
from packora.parsers import tls as tls_parser
from packora.parsers import transport as tp_parser

__all__ = ["parse_frame"]

DNS_PORT = 53
HTTP_PORTS = (80, 8080)
TLS_PORTS = (443, 8443)
DHCP_PORTS = (67, 68)
NTP_PORT = 123


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

    if frame.linktype in {12, 101}:  # DLT_RAW and LINKTYPE_RAW
        if not frame.raw:
            return broken("empty raw-IP frame")
        version = frame.raw[0] >> 4
        ethertype = eth_parser.ETHERTYPE_IP if version == 4 else eth_parser.ETHERTYPE_IPV6
        raw_eth = eth_parser.EtherFrame("", "", ethertype, frame.raw)
        ip = _decode_ipv4(frame.raw) if version == 4 else _decode_ipv6(frame.raw) if version == 6 else None
        if ip is None:
            return broken(f"truncated or malformed raw IPv{version} packet")
        return _packet_from_ip(frame, raw_eth, [], ip)

    try:
        eth = eth_parser.parse(frame.raw)
    except Exception:  # noqa: BLE001 - defensive by design (PRD N2)
        return broken("ethernet decode failed")
    if eth is None:
        return broken("truncated ethernet header (<14 bytes)")

    vlan_notes = [f"VLAN {vlan_id}" for vlan_id in eth.vlan_ids]
    if eth.ethertype == eth_parser.ETHERTYPE_ARP:
        return _decode_arp(frame, eth, vlan_notes)
    if eth.ethertype == eth_parser.ETHERTYPE_IP:
        ip = _decode_ipv4(eth.payload)
    elif eth.ethertype == eth_parser.ETHERTYPE_IPV6:
        ip = _decode_ipv6(eth.payload)
    else:
        return PacketInfo(
            ts=frame.ts,
            wire_len=len(frame.raw),
            classification=Classification.UNSUPPORTED,
            src_mac=eth.src_mac,
            dst_mac=eth.dst_mac,
            ethertype=eth.ethertype,
            unsupported_protocol=eth_parser.ethertype_note(eth.ethertype),
            payload_preview=_hex_preview(eth.payload),
            notes=vlan_notes,
        )
    if ip is None:
        layer = "IPv4" if eth.ethertype == eth_parser.ETHERTYPE_IP else "IPv6"
        return broken(f"truncated or malformed {layer} packet")

    return _packet_from_ip(frame, eth, vlan_notes, ip)


def _packet_from_ip(frame: Frame, eth: eth_parser.EtherFrame, vlan_notes: list[str], ip) -> PacketInfo:
    proto_name = _protocol_name(ip.proto, eth.ethertype)
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
        notes=vlan_notes,
    )
    try:
        if ip.proto == ip_parser.IPPROTO_TCP:
            _decode_tcp(pkt, ip.payload)
        elif ip.proto == ip_parser.IPPROTO_UDP:
            _decode_udp(pkt, ip.payload)
        elif ip.proto == ip_parser.IPPROTO_ICMP or ip.proto == ipv6_parser.IPPROTO_ICMPV6:
            _decode_icmp(pkt, ip.payload, ip.proto == ipv6_parser.IPPROTO_ICMPV6)
        else:
            pkt.classification = Classification.UNSUPPORTED
            pkt.unsupported_protocol = ip_parser.IPPROTO_OUT_OF_SCOPE.get(
                ip.proto, f"unsupported IPv4 protocol {ip.proto}"
            )
            pkt.payload_preview = _hex_preview(ip.payload)
    except Exception:  # noqa: BLE001 - classification contract: no payload parser may escape
        pkt.classification = Classification.MALFORMED
        pkt.malformed_reason = "transport or application decode failed"
        pkt.payload_preview = _hex_preview(ip.payload)
    return pkt


def _decode_ipv4(payload: bytes):
    try:
        return ip_parser.parse(payload)
    except Exception:  # noqa: BLE001 - parser boundary must never leak errors
        return None


def _decode_ipv6(payload: bytes):
    try:
        return ipv6_parser.parse(payload)
    except Exception:  # noqa: BLE001 - parser boundary must never leak errors
        return None


def _decode_arp(frame: Frame, eth: eth_parser.EtherFrame, vlan_notes: list[str]) -> PacketInfo:
    arp = arp_parser.parse(eth.payload)
    if arp is None:
        return PacketInfo(
            ts=frame.ts,
            wire_len=len(frame.raw),
            classification=Classification.MALFORMED,
            src_mac=eth.src_mac,
            dst_mac=eth.dst_mac,
            ethertype=eth.ethertype,
            malformed_reason="truncated or unsupported ARP packet",
            payload_preview=_hex_preview(eth.payload),
            notes=vlan_notes,
        )
    return PacketInfo(
        ts=frame.ts,
        wire_len=len(frame.raw),
        classification=Classification.PARSED,
        src_mac=eth.src_mac,
        dst_mac=eth.dst_mac,
        ethertype=eth.ethertype,
        src_ip=arp.sender_ip,
        dst_ip=arp.target_ip,
        proto_name="ARP",
        arp_sender_ip=arp.sender_ip,
        arp_sender_mac=arp.sender_mac,
        arp_target_ip=arp.target_ip,
        notes=[*vlan_notes, f"ARP {arp.operation} {arp.sender_ip} is-at {arp.sender_mac}"],
        payload_preview=_hex_preview(eth.payload),
    )


def _protocol_name(proto: int, ethertype: int) -> str:
    if ethertype == eth_parser.ETHERTYPE_IPV6 and proto == ipv6_parser.IPPROTO_ICMPV6:
        return "ICMPv6"
    return ip_parser.IPPROTO_NAMES.get(proto, f"proto {proto}")


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
    if seg.payload and (pkt.dst_port in HTTP_PORTS or pkt.src_port in HTTP_PORTS):
        http_decode = http_parser.parse(seg.payload)
        pkt.http = http_decode.info
        if http_decode.info is None and http_decode.failed:
            pkt.notes.append("HTTP-like payload did not decode")
    if seg.payload and (pkt.dst_port in TLS_PORTS or pkt.src_port in TLS_PORTS):
        tls_decode = tls_parser.parse(seg.payload)
        pkt.tls = tls_decode.info
        if tls_decode.info is not None:
            pkt.proto_name = "TLS"
        elif tls_decode.failed:
            pkt.notes.append("malformed TLS handshake record")
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
        dns_decode = dns_parser.parse(dgram.payload)
        if dns_decode.info is None:
            pkt.notes.append("DNS decode failed (kept as transport-only UDP)")
            return
        pkt.dns = dns_decode.info
        pkt.proto_name = "DNS"
    elif pkt.dst_port in DHCP_PORTS or pkt.src_port in DHCP_PORTS:
        dhcp_decode = dhcp_parser.parse(dgram.payload)
        if dhcp_decode.info is not None:
            pkt.dhcp = dhcp_decode.info
            pkt.proto_name = "DHCP"
        elif dhcp_decode.failed:
            pkt.notes.append("malformed DHCP options")
    elif pkt.dst_port == NTP_PORT or pkt.src_port == NTP_PORT:
        info = ntp_parser.parse(dgram.payload)
        if info is not None:
            pkt.ntp = info
            pkt.proto_name = "NTP"


def _decode_icmp(pkt: PacketInfo, payload: bytes, ipv6: bool) -> None:
    info = icmp_parser.parse(payload, ipv6=ipv6)
    if info is None:
        pkt.classification = Classification.MALFORMED
        pkt.malformed_reason = "truncated ICMP header"
        return
    pkt.proto_name = "ICMPv6" if ipv6 else "ICMP"
    pkt.payload_len = max(0, len(payload) - 4)
    pkt.app_payload = payload[4:]
    pkt.payload_preview = _hex_preview(payload)
    pkt.notes.append(f"{pkt.proto_name} {info.kind} (type={info.type}, code={info.code})")
