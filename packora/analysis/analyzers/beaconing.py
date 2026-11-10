"""Low-noise periodic outbound-flow heuristic for investigation prioritisation."""

from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.models.packet import PacketInfo


class BeaconingDetector(Analyzer):
    """Detect regular, repeated client-to-server payload timing; never labels malware."""

    def __init__(
        self,
        threshold: int = 6,
        max_jitter_ratio: float = 0.15,
        min_interval_seconds: float = 5.0,
        cooldown_seconds: float = 300.0,
    ) -> None:
        self.threshold = threshold
        self.max_jitter_ratio = max_jitter_ratio
        self.min_interval_seconds = min_interval_seconds
        self.cooldown_seconds = cooldown_seconds
        self._events: defaultdict[tuple[str, str, int, int, int], deque[float]] = defaultdict(deque)
        self._last_alerted: dict[tuple[str, str, int, int, int], float] = {}

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        if not (pkt.src_ip and pkt.dst_ip and pkt.src_port is not None and pkt.dst_port is not None):
            return []
        if pkt.payload_len == 0 or pkt.ip_proto not in {6, 17}:
            return []
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.ip_proto)
        events = self._events[key]
        events.append(pkt.ts)
        while len(events) > self.threshold:
            events.popleft()
        if len(events) < self.threshold:
            return []
        intervals = [later - earlier for earlier, later in zip(events, list(events)[1:], strict=False)]
        average = mean(intervals)
        if average < self.min_interval_seconds:
            return []
        jitter = max(abs(interval - average) for interval in intervals) / average
        if jitter > self.max_jitter_ratio:
            return []
        last = self._last_alerted.get(key)
        if last is not None and pkt.ts - last < self.cooldown_seconds:
            return []
        self._last_alerted[key] = pkt.ts
        return [
            Alert(
                ts=pkt.ts,
                kind="periodic_beaconing",
                src=pkt.src_ip,
                evidence=(
                    f"{self.threshold} payloads to {pkt.dst_ip}:{pkt.dst_port} every "
                    f"{average:.1f}s (jitter {jitter:.0%})"
                ),
                recommendation="Check whether the destination is an expected polling or telemetry service.",
            )
        ]
