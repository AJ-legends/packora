"""ARP mapping-conflict detection for local-network visibility."""

from __future__ import annotations

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.models.packet import PacketInfo


class ArpSpoofDetector(Analyzer):
    """Alert when one IPv4 address claims different MAC addresses in a capture."""

    def __init__(self, cooldown_seconds: float = 300.0) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._mappings: dict[str, str] = {}
        self._last_alerted: dict[str, float] = {}

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        ip, mac = pkt.arp_sender_ip, pkt.arp_sender_mac
        if not ip or not mac:
            return []
        previous = self._mappings.get(ip)
        self._mappings[ip] = mac
        if previous is None or previous == mac:
            return []
        last = self._last_alerted.get(ip)
        if last is not None and pkt.ts - last < self.cooldown_seconds:
            return []
        self._last_alerted[ip] = pkt.ts
        return [
            Alert(
                ts=pkt.ts,
                kind="arp_mapping_conflict",
                src=ip,
                evidence=f"ARP sender mapping changed from {previous} to {mac}",
                recommendation="Confirm the expected gateway/device MAC address before treating this as spoofing.",
            )
        ]
