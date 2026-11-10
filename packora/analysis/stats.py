"""Protocol-mix and throughput statistics (PRD F5.1, F5.6, N3)."""

from __future__ import annotations

import time
from collections import Counter, deque
from enum import StrEnum

from packora.models.packet import Classification, PacketInfo

RATE_WINDOW_SECONDS = 2.0


class StatBucket(StrEnum):
    """Protocol-mix buckets; DNS/HTTP get their own labels, transport stays generic."""

    TCP = "TCP"
    UDP = "UDP"
    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS"
    DHCP = "DHCP"
    NTP = "NTP"
    ARP = "ARP"
    ICMP = "ICMP"
    OTHER_PARSED = "other"
    UNSUPPORTED = "unsupported"
    MALFORMED = "malformed"


class StatsTracker:
    """Aggregates counts + packets/sec. Updated by the controller thread; UI read-only."""

    def __init__(self, rate_window: float = RATE_WINDOW_SECONDS) -> None:
        self.rate_window = rate_window
        self.counts: Counter[str] = Counter()
        self.total = 0
        self._timestamps: deque[float] = deque()

    def observe(self, pkt: PacketInfo) -> None:
        self.counts[self.bucket_for(pkt)] += 1
        self.total += 1
        self._timestamps.append(pkt.ts)

    @staticmethod
    def bucket_for(pkt: PacketInfo) -> str:
        if pkt.classification is Classification.MALFORMED:
            return StatBucket.MALFORMED
        if pkt.classification is Classification.UNSUPPORTED:
            return StatBucket.UNSUPPORTED
        if pkt.dns is not None:
            return StatBucket.DNS
        if pkt.http is not None:
            return StatBucket.HTTP
        if pkt.tls is not None:
            return StatBucket.TLS
        if pkt.dhcp is not None:
            return StatBucket.DHCP
        if pkt.ntp is not None:
            return StatBucket.NTP
        if pkt.arp_sender_ip is not None:
            return StatBucket.ARP
        if pkt.proto_name in {"ICMP", "ICMPv6"}:
            return StatBucket.ICMP
        if pkt.ip_proto == 6:
            return StatBucket.TCP
        if pkt.ip_proto == 17:
            return StatBucket.UDP
        return StatBucket.OTHER_PARSED

    def rate_per_second(self, reference_ts: float | None = None) -> float:
        """Packets within the trailing window (N3: rate is derived, never accumulated)."""
        if not self._timestamps:
            return 0.0
        ref = reference_ts if reference_ts is not None else self._timestamps[-1]
        horizon = ref - self.rate_window
        while self._timestamps and self._timestamps[0] < horizon:
            self._timestamps.popleft()
        return len(self._timestamps) / self.rate_window

    def mix(self) -> list[tuple[str, int]]:
        """Buckets sorted by count desc for the protocol-mix panel."""
        return self.counts.most_common()

    def classification_counts(self) -> Counter[str]:
        return Counter(
            {
                Classification.PARSED.value: sum(
                    n for k, n in self.counts.items() if k not in ("unsupported", "malformed")
                ),
                "unsupported": self.counts["unsupported"],
                "malformed": self.counts["malformed"],
            }
        )


def now_wall() -> float:
    return time.time()
