"""Defensive IPv6 parsing with common extension-header traversal."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

IPPROTO_HOPOPT = 0
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_DSTOPTS = 60
IPPROTO_ICMPV6 = 58

_EXTENSION_HEADERS = {IPPROTO_HOPOPT, IPPROTO_ROUTING, IPPROTO_DSTOPTS}


@dataclass(frozen=True)
class Ipv6Packet:
    src_ip: str
    dst_ip: str
    proto: int
    payload: bytes


def parse(data: bytes) -> Ipv6Packet | None:
    """Parse fixed header plus safe, bounded common IPv6 extension headers."""
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    payload_length = int.from_bytes(data[4:6], "big")
    end = 40 + payload_length
    if len(data) < end:
        return None
    next_header = data[6]
    cursor = 40
    for _ in range(8):  # bounded to avoid malformed extension-header loops
        if next_header in _EXTENSION_HEADERS:
            if cursor + 2 > end:
                return None
            following = data[cursor]
            size = (data[cursor + 1] + 1) * 8
            if size < 8 or cursor + size > end:
                return None
            next_header, cursor = following, cursor + size
            continue
        if next_header == IPPROTO_FRAGMENT:
            if cursor + 8 > end:
                return None
            next_header, cursor = data[cursor], cursor + 8
            continue
        if next_header == IPPROTO_AH:
            if cursor + 2 > end:
                return None
            following = data[cursor]
            size = (data[cursor + 1] + 2) * 4
            if size < 8 or cursor + size > end:
                return None
            next_header, cursor = following, cursor + size
            continue
        break
    return Ipv6Packet(
        src_ip=str(ipaddress.IPv6Address(data[8:24])),
        dst_ip=str(ipaddress.IPv6Address(data[24:40])),
        proto=next_header,
        payload=data[cursor:end],
    )
