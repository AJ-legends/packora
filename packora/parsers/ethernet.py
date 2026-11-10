"""Ethernet II frame parsing (PRD F2.1, F2.2)."""

from __future__ import annotations

from dataclasses import dataclass

ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_VLAN_9100 = 0x9100

_VLAN_ETHERTYPES = {ETHERTYPE_VLAN, ETHERTYPE_QINQ, ETHERTYPE_VLAN_9100}

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
    vlan_ids: tuple[int, ...] = ()


def parse(frame: bytes) -> EtherFrame | None:
    """Parse an Ethernet II header. Returns None when the frame is structurally unusable."""
    if len(frame) < 14:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    cursor = 14
    vlan_ids: list[int] = []
    while ethertype in _VLAN_ETHERTYPES:
        if cursor + 4 > len(frame):
            return None
        vlan_ids.append(int.from_bytes(frame[cursor : cursor + 2], "big") & 0x0FFF)
        ethertype = int.from_bytes(frame[cursor + 2 : cursor + 4], "big")
        cursor += 4
    return EtherFrame(
        dst_mac=format_mac(frame[0:6]),
        src_mac=format_mac(frame[6:12]),
        ethertype=ethertype,
        payload=frame[cursor:],
        vlan_ids=tuple(vlan_ids),
    )
