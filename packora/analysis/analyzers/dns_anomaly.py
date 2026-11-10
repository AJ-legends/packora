"""DNS anomaly detection (PRD F4.3 stretch, v2): rapid distinct-name querying per source."""

from __future__ import annotations

from collections import defaultdict, deque

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.models.packet import PacketInfo


class DnsAnomalyDetector(Analyzer):
    """Alerts when a source queries >= threshold distinct DNS names within the window."""

    def __init__(
        self,
        threshold: int = 100,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 60.0,
        evidence_sample_size: int = 8,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.evidence_sample_size = evidence_sample_size
        self._queries: defaultdict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._last_alerted: dict[str, float] = {}

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        dns = pkt.dns
        if dns is None or dns.is_response or not dns.name:
            return []
        if pkt.src_ip is None:
            return []
        src = pkt.src_ip
        now = pkt.ts
        window = self._queries[src]
        window.append((now, dns.name))
        horizon = now - self.window_seconds
        while window and window[0][0] < horizon:
            window.popleft()
        distinct = {name for _, name in window}
        if len(distinct) < self.threshold:
            return []
        last = self._last_alerted.get(src)
        if last is not None and now - last < self.cooldown_seconds:
            return []
        self._last_alerted[src] = now
        sample = sorted(distinct)[: self.evidence_sample_size]
        suffix = "..." if len(distinct) > len(sample) else ""
        return [
            Alert(
                ts=pkt.ts,
                kind="dns_anomaly",
                src=src,
                evidence=(
                    f"{len(distinct)} distinct DNS names queried within "
                    f"{self.window_seconds:.0f}s ({sample}{suffix})"
                ),
                recommendation=(
                    "Possible DNS scanning or data exfiltration. Review the queried "
                    "names for lookalike or tunnelled (very long/dotted) domains."
                ),
            )
        ]
