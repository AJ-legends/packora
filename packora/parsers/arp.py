"""ARP parsing for Ethernet/IPv4 address resolution traffic."""

from __future__ import annotations

from dataclasses import dataclass


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _ipv4(raw: bytes) -> str:
    return ".".join(str(byte) for byte in raw)


@dataclass(frozen=True)
class ArpPacket:
    operation: str
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


def parse(data: bytes) -> ArpPacket | None:
    """Decode Ethernet/IPv4 ARP; other hardware layouts are out of scope."""
    if len(data) < 28:
        return None
    hardware_type = int.from_bytes(data[0:2], "big")
    protocol_type = int.from_bytes(data[2:4], "big")
    hardware_len, protocol_len = data[4], data[5]
    if hardware_type != 1 or protocol_type != 0x0800 or hardware_len != 6 or protocol_len != 4:
        return None
    operation = {1: "request", 2: "reply"}.get(int.from_bytes(data[6:8], "big"), "other")
    return ArpPacket(
        operation=operation,
        sender_mac=_mac(data[8:14]),
        sender_ip=_ipv4(data[14:18]),
        target_mac=_mac(data[18:24]),
        target_ip=_ipv4(data[24:28]),
    )
