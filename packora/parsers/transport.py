"""TCP and UDP segment parsing (PRD F2.1)."""

from __future__ import annotations

from dataclasses import dataclass

from packora.models.packet import TcpFlags


@dataclass(frozen=True)
class TcpSegment:
    sport: int
    dport: int
    seq: int
    ack_seq: int
    flags: TcpFlags
    window: int
    payload: bytes


@dataclass(frozen=True)
class UdpDatagram:
    sport: int
    dport: int
    payload: bytes


def parse_flags(raw: int) -> TcpFlags:
    return TcpFlags(
        fin=bool(raw & 0x01),
        syn=bool(raw & 0x02),
        rst=bool(raw & 0x04),
        psh=bool(raw & 0x08),
        ack=bool(raw & 0x10),
        urg=bool(raw & 0x20),
    )


def parse_tcp(data: bytes) -> TcpSegment | None:
    """Parse a TCP segment header. Returns None when structurally unusable."""
    if len(data) < 20:
        return None
    data_offset_words = data[12] >> 4
    header_len = data_offset_words * 4
    if data_offset_words < 5 or len(data) < header_len:
        return None
    return TcpSegment(
        sport=int.from_bytes(data[0:2], "big"),
        dport=int.from_bytes(data[2:4], "big"),
        seq=int.from_bytes(data[4:8], "big"),
        ack_seq=int.from_bytes(data[8:12], "big"),
        flags=parse_flags(data[13]),
        window=int.from_bytes(data[14:16], "big"),
        payload=data[header_len:],
    )


def parse_udp(data: bytes) -> UdpDatagram | None:
    """Parse a UDP datagram header. Returns None when structurally unusable."""
    if len(data) < 8:
        return None
    datagram_len = int.from_bytes(data[4:6], "big")
    if datagram_len < 8 or datagram_len > len(data):
        return None
    return UdpDatagram(
        sport=int.from_bytes(data[0:2], "big"),
        dport=int.from_bytes(data[2:4], "big"),
        payload=data[8:datagram_len],
    )
