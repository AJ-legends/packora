"""ICMP and ICMPv6 header parsing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IcmpPacket:
    kind: str
    type: int
    code: int


_ICMP_TYPES = {0: "echo_reply", 3: "destination_unreachable", 5: "redirect", 8: "echo_request", 11: "time_exceeded"}
_ICMPV6_TYPES = {1: "destination_unreachable", 2: "packet_too_big", 3: "time_exceeded", 128: "echo_request", 129: "echo_reply", 135: "neighbor_solicitation", 136: "neighbor_advertisement"}


def parse(data: bytes, ipv6: bool = False) -> IcmpPacket | None:
    if len(data) < 4:
        return None
    type_value, code = data[0], data[1]
    names = _ICMPV6_TYPES if ipv6 else _ICMP_TYPES
    return IcmpPacket(kind=names.get(type_value, f"type_{type_value}"), type=type_value, code=code)
