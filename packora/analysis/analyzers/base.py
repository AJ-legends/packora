"""Detection analyzer contract (PRD F4, v2)."""

from __future__ import annotations

from dataclasses import dataclass

from packora.models.packet import PacketInfo


class Analyzer:
    """Base: `observe` one packet at a time, returning any alerts the packet triggers."""

    def observe(self, pkt: PacketInfo) -> list[Alert]:
        return []

    def finalize(self, ts: float) -> list[Alert]:
        """Flush time-delayed evidence when a feed ends.

        TCP response matching needs a short grace period so a SYN is not
        reported before its SYN-ACK has had a chance to appear in the capture.
        Live callers continue to evaluate on every packet; replay callers also
        invoke this hook once at end-of-feed.
        """
        return []


@dataclass(frozen=True)
class Alert:
    """One detection event destined for the alerts panel / CLI (PRD F4.4)."""

    ts: float
    kind: str
    src: str
    evidence: str
    recommendation: str = ""

    def one_liner(self) -> str:
        from datetime import datetime

        stamp = datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")
        return f"{stamp} {self.kind} {self.src}: {self.evidence}"


@dataclass
class DetectionConfig:
    """Thresholds, all CLI-configurable (PRD section 10, D-6)."""

    enabled: bool = True
    scan_threshold: int = 10
    flood_threshold: int = 100
    dns_threshold: int = 100
