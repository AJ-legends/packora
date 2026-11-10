"""Port-scan detection (PRD F4.1): sliding-window unique SYN-port counter per source."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.models.packet import PacketInfo


@dataclass
class _Probe:
    ts: float
    dst_ip: str
    src_port: int
    dst_port: int


class PortScanDetector(Analyzer):
    """Alerts when one source SYN-probes >= threshold distinct ports within the window.

    Threshold is configurable (default 10, PRD section 10 D-6) and each source has a
    cooldown so one scanning host produces a bounded number of alerts.
    """

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 60.0,
        evidence_sample_size: int = 12,
        response_grace_seconds: float = 1.0,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.evidence_sample_size = evidence_sample_size
        self.response_grace_seconds = response_grace_seconds
        self._probes: defaultdict[str, list[_Probe]] = defaultdict(list)
        self._last_alerted: dict[str, float] = {}

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        now = pkt.ts
        self._mark_response(pkt)
        if pkt.tcp_flags and pkt.tcp_flags.is_syn_without_ack and pkt.src_ip and pkt.dst_ip:
            self._probes[pkt.src_ip].append(
                _Probe(now, pkt.dst_ip, pkt.src_port or 0, pkt.dst_port or 0)
            )
        return self._evaluate(now)

    def finalize(self, ts: float) -> list[Alert]:
        return self._evaluate(ts + self.response_grace_seconds)

    def _mark_response(self, pkt: PacketInfo) -> None:
        """Remove the originating SYN when its reverse SYN-ACK is observed."""
        flags = pkt.tcp_flags
        if not (flags and flags.is_synack and pkt.src_ip and pkt.dst_ip):
            return
        source = pkt.dst_ip
        self._probes[source] = [
            probe
            for probe in self._probes[source]
            if not (
                probe.dst_ip == pkt.src_ip
                and probe.dst_port == (pkt.src_port or 0)
                and probe.src_port == (pkt.dst_port or 0)
            )
        ]

    def _evaluate(self, now: float) -> list[Alert]:
        alerts: list[Alert] = []
        horizon = now - self.window_seconds
        eligible_before = now - self.response_grace_seconds
        for src, probes in self._probes.items():
            self._probes[src] = [probe for probe in probes if probe.ts >= horizon]
            distinct_ports = {probe.dst_port for probe in self._probes[src] if probe.ts <= eligible_before}
            if len(distinct_ports) < self.threshold:
                continue
            last = self._last_alerted.get(src)
            if last is not None and now - last < self.cooldown_seconds:
                continue
            self._last_alerted[src] = now
            sample_ports = sorted(distinct_ports)[: self.evidence_sample_size]
            suffix = "..." if len(distinct_ports) > len(sample_ports) else ""
            alerts.append(
                Alert(
                    ts=now,
                    kind="port_scan",
                    src=src,
                    evidence=(
                        f"{len(distinct_ports)} unanswered SYN probes to distinct ports within "
                        f"{self.window_seconds:.0f}s ({sample_ports}{suffix})"
                    ),
                    recommendation="Possible port scan. Inspect this source's conversations and service logs.",
                )
            )
        return alerts
