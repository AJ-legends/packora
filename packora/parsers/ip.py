"""IPv4 header parsing (PRD F2.1)."""

from __future__ import annotations

from dataclasses import dataclass

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

IPPROTO_NAMES = {
    IPPROTO_ICMP: "ICMP",
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
}

IPPROTO_OUT_OF_SCOPE = {
    IPPROTO_ICMP: "ICMP (proto 1) is out of scope for Packora v1",
}

_IPV6_NEXT_HEADER_NAMES = {6, 17}


def format_ip(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


@dataclass(frozen=True)
class IpPacket:
    src_ip: str
    dst_ip: str
    proto: int
    payload: bytes


def parse(data: bytes) -> IpPacket | None:
    """Parse the IPv4 portion of a frame payload. Returns None when structurally unusable."""
    if len(data) < 20:
        return None
    version = data[0] >> 4
    if version != 4:
        return None
    ihl_words = data[0] & 0x0F
    if ihl_words < 5:
        return None  # options-extended min IHL is 5 words (20 bytes)
    ihl = ihl_words * 4
    total_len = int.from_bytes(data[2:4], "big")
    if total_len < ihl or len(data) < ihl or len(data) < total_len:
        return None
    payload = data[ihl:total_len]
    return IpPacket(
        src_ip=format_ip(data[12:16]),
        dst_ip=format_ip(data[16:20]),
        proto=data[9],
        payload=payload,
    )
