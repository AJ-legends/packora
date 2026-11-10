"""Session grouping and TCP reassembly (PRD F3, v2).

Conversations merge both directions under one canonical key; segment data is
fed to a per-direction reassembler which orders, dedupes, and marks gaps.
"""

from __future__ import annotations

from dataclasses import dataclass

from packora.models.packet import PacketInfo
from packora.models.session import Conversation


def conversation_key(pkt: PacketInfo) -> tuple | None:
    """Direction-independent conversation key, or None for non-transport packets."""
    if pkt.src_ip is None or pkt.dst_ip is None:
        return None
    a = (pkt.src_ip, pkt.src_port or 0)
    b = (pkt.dst_ip, pkt.dst_port or 0)
    first, second = sorted([a, b])
    return (pkt.ip_proto, first, second)


class SessionTracker:
    """Accumulates conversations; the analysis controller calls `observe` per packet."""

    def __init__(self) -> None:
        self.conversations: dict[tuple, Conversation] = {}
        self.order: list[tuple] = []

    def observe(self, pkt: PacketInfo) -> Conversation | None:
        conv_key = conversation_key(pkt)
        if conv_key is None:
            return None
        conv = self.conversations.get(conv_key)
        if conv is None:
            src = (pkt.src_ip or "", pkt.src_port or 0)
            dst = (pkt.dst_ip or "", pkt.dst_port or 0)
            conv = Conversation(
                proto=pkt.proto_name or "",
                key=conv_key,
                started_ts=pkt.ts,
                client=src,
                server=dst,
            )
            self.conversations[conv_key] = conv
            self.order.append(conv_key)
        conv.packets += 1
        conv.bytes_total += pkt.wire_len
        if pkt.tcp_flags and pkt.payload_len and pkt.src_ip is not None and pkt.seq is not None:
            stream = conv.stream_for((pkt.src_ip, pkt.src_port or 0))
            stream.add(_app_seq(pkt), pkt.app_payload)
        return conv

    def ordered(self) -> list[Conversation]:
        return [self.conversations[key] for key in self.order]


def _app_seq(pkt: PacketInfo) -> int:
    """Absolute TCP sequence number of the first app-payload byte (seq + SYN offset)."""
    assert pkt.seq is not None
    seq = pkt.seq
    if pkt.tcp_flags and pkt.tcp_flags.syn:
        seq += 1  # SYN consumes one sequence number
    return seq


def render_conversation_table(conversations: list[Conversation]) -> list[list[object]]:
    """Rows for the sessions view (PRD F5.2): idx, proto, endpoints, pkts, bytes, gaps."""
    rows: list[list[object]] = []
    for idx, conv in enumerate(conversations, start=1):
        rows.append(
            [
                idx,
                conv.proto,
                f"{conv.client[0]}:{conv.client[1]}",
                f"{conv.server[0]}:{conv.server[1]}",
                conv.packets,
                conv.bytes_total,
                conv.missing_segments,
            ]
        )
    return rows


@dataclass(frozen=True)
class SessionSummary:
    proto: str
    client: str
    server: str
    packets: int
    bytes_total: int
    gaps: int
