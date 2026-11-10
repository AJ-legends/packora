"""PCAP replay feed (PRD F1.3).

The featured path for demos and tests: no privileges, no live network, fully
reproducible. scapy stays in capture/; callers only see `Frame`s.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

from packora.capture.base import Frame


class ReplayFeed:
    """Stream frames from a pcap file. Optional real-time pacing for demos."""

    def __init__(self, path: str, speed: float = 0.0) -> None:
        self.path = path
        self.speed = speed  # 0 = as-fast-as-possible; 1 = capture rate; 2 = 2x capture rate

    @property
    def description(self) -> str:
        return f"replay:{self.path}"

    def frames(self) -> Iterator[Frame]:
        from scapy.all import PcapReader

        with PcapReader(self.path) as reader:
            previous_ts: float | None = None
            for pkt in reader:
                ts = float(pkt.time)
                if self.speed > 0 and previous_ts is not None:
                    delay = (ts - previous_ts) / self.speed
                    if delay > 0:
                        time.sleep(delay)
                previous_ts = ts
                yield Frame(ts=ts, raw=bytes(pkt))
