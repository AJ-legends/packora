"""DNS-tunnelling heuristic based on repeated long, distinct query labels."""

from __future__ import annotations

from collections import defaultdict, deque

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.models.packet import PacketInfo


class DnsTunnelDetector(Analyzer):
    def __init__(
        self,
        threshold: int = 8,
        min_label_length: int = 35,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 120.0,
    ) -> None:
        self.threshold = threshold
        self.min_label_length = min_label_length
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self._queries: defaultdict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._last_alerted: dict[str, float] = {}

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        if pkt.dns is None or pkt.dns.is_response or pkt.src_ip is None:
            return []
        labels = pkt.dns.name.split(".")
        if not labels or len(labels[0]) < self.min_label_length:
            return []
        entries = self._queries[pkt.src_ip]
        entries.append((pkt.ts, pkt.dns.name))
        horizon = pkt.ts - self.window_seconds
        while entries and entries[0][0] < horizon:
            entries.popleft()
        names = {name for _, name in entries}
        if len(names) < self.threshold:
            return []
        last = self._last_alerted.get(pkt.src_ip)
        if last is not None and pkt.ts - last < self.cooldown_seconds:
            return []
        self._last_alerted[pkt.src_ip] = pkt.ts
        return [
            Alert(
                ts=pkt.ts,
                kind="dns_tunnel_suspected",
                src=pkt.src_ip,
                evidence=(
                    f"{len(names)} distinct queries with a first label >= {self.min_label_length} characters "
                    f"within {self.window_seconds:.0f}s"
                ),
                recommendation="Review this source and queried domains for approved telemetry before escalating.",
            )
        ]
