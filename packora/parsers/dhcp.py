"""Minimal DHCPv4 option parsing without retaining client identifiers."""

from __future__ import annotations

from dataclasses import dataclass

from packora.models.packet import DhcpInfo

_MESSAGE_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}


@dataclass(frozen=True)
class DhcpDecode:
    info: DhcpInfo | None
    failed: bool


def parse(data: bytes) -> DhcpDecode:
    """Decode a BOOTP/DHCPv4 payload only when the RFC cookie is present."""
    if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
        return DhcpDecode(None, False)
    message_type: int | None = None
    hostname: str | None = None
    requested_ip: str | None = None
    cursor = 240
    while cursor < len(data):
        option = data[cursor]
        cursor += 1
        if option == 255:
            break
        if option == 0:
            continue
        if cursor >= len(data):
            return DhcpDecode(None, True)
        size = data[cursor]
        cursor += 1
        if cursor + size > len(data):
            return DhcpDecode(None, True)
        value = data[cursor : cursor + size]
        cursor += size
        if option == 53 and size == 1:
            message_type = value[0]
        elif option == 12:
            hostname = value.decode("ascii", errors="replace")[:63]
        elif option == 50 and size == 4:
            requested_ip = ".".join(str(byte) for byte in value)
    if message_type is None:
        return DhcpDecode(None, True)
    return DhcpDecode(DhcpInfo(_MESSAGE_TYPES.get(message_type, f"type_{message_type}"), hostname, requested_ip), False)
