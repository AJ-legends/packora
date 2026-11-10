"""Capture feed protocol: the single interface every frame source satisfies.

Both `LiveCapture` and `ReplayFeed` return `Frame` objects, so everything
downstream (parsing, analysis, UI) is identical for live vs replay traffic
(PRD F1.3, sections 6 "Feed contract").
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Frame:
    """One raw captured frame (ethernet or raw layer-2 bytes) with its capture timestamp."""

    ts: float
    raw: bytes

    @property
    def wire_len(self) -> int:
        return len(self.raw)


class Feed(Protocol):
    """Anything that can yield captured frames. Parsers and analysis only ever see this."""

    @property
    def description(self) -> str:
        ...

    def frames(self) -> Iterator[Frame]:
        ...
