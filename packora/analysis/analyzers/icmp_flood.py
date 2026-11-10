"""ICMP echo-request burst detection."""

from __future__ import annotations

from collections import defaultdict, deque

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.models.packet import PacketInfo


class IcmpFloodDetector(Analyzer):
    def __init__(self, threshold: int = 50, window_seconds: float = 10.0, cooldown_seconds: float = 60.0) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self._requests: defaultdict[str, deque[float]] = defaultdict(deque)
        self._last_alerted: dict[str, float] = {}

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        if pkt.proto_name not in {"ICMP", "ICMPv6"} or pkt.src_ip is None:
            return []
        if not any("echo_request" in note for note in pkt.notes):
            return []
        requests = self._requests[pkt.src_ip]
        requests.append(pkt.ts)
        horizon = pkt.ts - self.window_seconds
        while requests and requests[0] < horizon:
            requests.popleft()
        if len(requests) < self.threshold:
            return []
        last = self._last_alerted.get(pkt.src_ip)
        if last is not None and pkt.ts - last < self.cooldown_seconds:
            return []
        self._last_alerted[pkt.src_ip] = pkt.ts
        return [
            Alert(
                ts=pkt.ts,
                kind="icmp_flood",
                src=pkt.src_ip,
                evidence=f"{len(requests)} ICMP echo requests within {self.window_seconds:.0f}s",
                recommendation="Validate whether this is an approved diagnostic burst; otherwise inspect the source host.",
            )
        ]
