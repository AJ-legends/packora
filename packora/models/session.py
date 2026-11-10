"""Conversation/stream models for TCP reassembly (PRD F3, v2).

Reassembly design tolerance (deliberate, documented limits):
- Segments are ordered by sequence number relative to the first byte seen in
  that direction; an absolute sequence base is established on first use.
- Retransmissions/overlaps are deduplicated; a segment whose data is already
  covered contributes nothing.
- Gaps become inline markers `...N bytes missing...` rather than blocking.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StreamSegment:
    seq: int  # relative sequence number
    data: bytes


class StreamReassembler:
    """Byte-ordered reassembly for one direction of one TCP conversation."""

    def __init__(self, max_bytes: int = 2**20) -> None:
        self._segments: list[StreamSegment] = []
        self.max_bytes = max_bytes

    @property
    def base_seq(self) -> int | None:
        return min((s.seq for s in self._segments), default=None)

    def add(self, seq: int, data: bytes) -> None:
        """Record payload bytes at absolute TCP sequence `seq` (retransmits/overlaps OK)."""
        if not data:
            return
        first = self.base_seq
        if first is not None and abs(seq - first) > self.max_bytes:
            return  # sanity guard against wildly divergent streams
        self._segments.append(StreamSegment(seq, data))

    def _coalesce(self) -> list[StreamSegment]:
        """Order by sequence number and trim segment overlaps (retransmission dedupe)."""
        ordered = sorted(self._segments, key=lambda s: (s.seq, -len(s.data)))
        result: list[StreamSegment] = []
        frontier = 0
        base = self.base_seq
        if base is None:
            return []
        for seg in ordered:
            start, end = seg.seq - base, (seg.seq - base) + len(seg.data)
            if end <= frontier:  # fully covered by earlier data (retransmission)
                continue
            if start < frontier:  # partial overlap; keep the not-yet-covered tail
                data = seg.data[frontier - start :]
                start = frontier
            else:
                data = seg.data
            result.append(StreamSegment(start, data))
            frontier = start + len(data)
        return result

    def build(self) -> str:
        """Assemble ordered payload text; gaps get inline placeholders (PRD F3.2)."""
        out = bytearray()
        last_end = 0
        for seg in self._coalesce():
            if seg.seq > last_end:
                out.extend(f"...{seg.seq - last_end} bytes missing...".encode())
            out.extend(seg.data)
            last_end = seg.seq + len(seg.data)
        text = bytes(out).decode("latin-1", errors="replace")
        if len(text) > self.max_bytes:
            text = text[: self.max_bytes] + " ...[truncated]"
        return text

    def has_gaps(self) -> bool:
        expected = 0
        for seg in self._coalesce():
            if seg.seq > expected:
                return True
            expected = seg.seq + len(seg.data)
        return False

    def payload_bytes(self) -> int:
        return sum(len(s.data) for s in self._coalesce())


@dataclass
class Conversation:
    """One bidirectional conversation, identified by an order-independent 5-tuple key."""

    proto: str  # "TCP" | "UDP"
    key: tuple  # canonical sorted ((ip, port), (ip, port)) + proto
    started_ts: float
    packets: int = 0
    bytes_total: int = 0
    # Endpoints as displayed; assignment does not affect keying (sorted canonical).
    client: tuple[str, int] = ("", 0)   # endpoint that spoke first
    server: tuple[str, int] = ("", 0)   # endpoint that spoke second
    # Streams per direction: use endpoint key lookup rather than positional flags.
    streams: dict[tuple[str, int], StreamReassembler] = field(default_factory=dict)

    def stream_for(self, endpoint: tuple[str, int]) -> StreamReassembler:
        asmr = self.streams.get(endpoint)
        if asmr is None:
            asmr = StreamReassembler()
            self.streams[endpoint] = asmr
        return asmr

    @property
    def missing_segments(self) -> int:
        """Count of gaps flagged in either direction (PRD acceptance B "missing segments")."""
        count = 0
        for stream in self.streams.values():
            if stream.has_gaps():
                count += 1
        return count

    def reassembled_view(self, max_len: int = 4000) -> str:
        """Human-readable two-direction stream view: client vs server text is distinct (PRD F3.3)."""
        parts = [
            f"Conversation {self.proto} {self.client[0]}:{self.client[1]} -> {self.server[0]}:{self.server[1]}",
            f"packets={self.packets} bytes={self.bytes_total}",
        ]
        for label, endpoint in (("client -> server", self.client), ("server -> client", self.server)):
            stream = self.streams.get(endpoint)
            if stream is None:
                parts.append(f"--- {label}: (no payload)")
                continue
            text = stream.build()
            if len(text) > max_len:
                text = text[:max_len] + " ...[truncated]"
            parts.append(f"--- {label} ---")
            parts.append(text)
        return "\n".join(parts)

