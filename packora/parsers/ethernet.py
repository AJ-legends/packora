"""Ethernet II frame parsing (PRD F2.1, F2.2)."""

from __future__ import annotations

from dataclasses import dataclass

ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

_ETH_NAMES = {
    ETHERTYPE_IPV6: "IPv6 (0x86dd) is out of scope for Packora v1",
    ETHERTYPE_ARP: "ARP (0x0806) is out of scope for Packora v1",
    ETHERTYPE_VLAN: "VLAN tag (0x8100) is out of scope for Packora v1",
}


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ethertype_note(ethertype: int) -> str:
    """Explain why an ethertype is unsupported; the identifier is always included (F2.1)."""
    known = _ETH_NAMES.get(ethertype)
    if known:
        return known
    return f"unknown ethertype 0x{ethertype:04x}"


@dataclass(frozen=True)
class EtherFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes


def parse(frame: bytes) -> EtherFrame | None:
    """Parse an Ethernet II header. Returns None when the frame is structurally unusable."""
    if len(frame) < 14:
        return None
    if frame[12] == 0x81 and frame[13] == 0x00:
        # A VLAN-tagged frame's real next-protocol field sits two bytes deeper; Packora
        # reports the outer 0x8100 as unsupported rather than hiding it.
        ethertype = ETHERTYPE_VLAN
        payload = frame[14:]
        return EtherFrame(
            dst_mac=format_mac(frame[0:6]),
            src_mac=format_mac(frame[6:12]),
            ethertype=ethertype,
            payload=payload,
        )
    ethertype = int.from_bytes(frame[12:14], "big")
    return EtherFrame(
        dst_mac=format_mac(frame[0:6]),
        src_mac=format_mac(frame[6:12]),
        ethertype=ethertype,
        payload=frame[14:],
    )
