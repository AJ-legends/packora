"""SYN-flood detection (PRD F4.2, v2): volume of SYNs per source."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.models.packet import PacketInfo


@dataclass
class _Syn:
    ts: float
    dst_ip: str
    src_port: int
    dst_port: int
    answered: bool = False


class SynFloodDetector(Analyzer):
    """Alerts when a source emits >= threshold SYNs within the window.

    A deliberately coarse, educational heuristic (documented in PRD): bulk
    SYN bursts from one host are anomalous at the home/LAN scales Packora
    targets. Half-open handling: SYN-ACKs are simply not counted as probes;
    refinement ratios are left for a later iteration.
    """

    def __init__(
        self,
        threshold: int = 100,
        window_seconds: float = 10.0,
        cooldown_seconds: float = 60.0,
        unanswered_ratio: float = 0.8,
        response_grace_seconds: float = 1.0,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.unanswered_ratio = unanswered_ratio
        self.response_grace_seconds = response_grace_seconds
        self._syns: defaultdict[str, list[_Syn]] = defaultdict(list)
        self._last_alerted: dict[str, float] = {}

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        now = pkt.ts
        self._mark_response(pkt)
        if pkt.tcp_flags and pkt.tcp_flags.is_syn_without_ack and pkt.src_ip and pkt.dst_ip:
            self._syns[pkt.src_ip].append(
                _Syn(now, pkt.dst_ip, pkt.src_port or 0, pkt.dst_port or 0)
            )
        return self._evaluate(now)

    def finalize(self, ts: float) -> list[Alert]:
        return self._evaluate(ts + self.response_grace_seconds)

    def _mark_response(self, pkt: PacketInfo) -> None:
        flags = pkt.tcp_flags
        if not (flags and flags.is_synack and pkt.src_ip and pkt.dst_ip):
            return
        for syn in self._syns[pkt.dst_ip]:
            if (
                syn.dst_ip == pkt.src_ip
                and syn.dst_port == (pkt.src_port or 0)
                and syn.src_port == (pkt.dst_port or 0)
            ):
                syn.answered = True

    def _evaluate(self, now: float) -> list[Alert]:
        alerts: list[Alert] = []
        horizon = now - self.window_seconds
        eligible_before = now - self.response_grace_seconds
        for src, events in self._syns.items():
            self._syns[src] = [event for event in events if event.ts >= horizon]
            eligible = [event for event in self._syns[src] if event.ts <= eligible_before]
            unanswered = [event for event in eligible if not event.answered]
            ratio = len(unanswered) / len(eligible) if eligible else 0.0
            if len(unanswered) < self.threshold or ratio < self.unanswered_ratio:
                continue
            last = self._last_alerted.get(src)
            if last is not None and now - last < self.cooldown_seconds:
                continue
            self._last_alerted[src] = now
            alerts.append(
                Alert(
                    ts=now,
                    kind="syn_flood",
                    src=src,
                    evidence=(
                        f"{len(unanswered)}/{len(eligible)} unanswered SYNs "
                        f"within {self.window_seconds:.0f}s ({ratio:.0%} unanswered)"
                    ),
                    recommendation=(
                        "Possible SYN flood. Verify destination service state and consider "
                        "rate-limiting or blocking the source."
                    ),
                )
            )
        return alerts
