"""TCP session grouping + stream reassembly tests (PRD F3)."""

from __future__ import annotations

from packora.analysis.sessions import SessionTracker
from packora.models.packet import Classification, PacketInfo, TcpFlags

CLIENT = "10.0.0.5"
SERVER = "93.184.216.10"
SPORT = 12345


def tcp_pkt(
    direction: str = "c2s",
    seq: int = 1000,
    payload: bytes = b"",
    ts: float = 1.0,
    syn: bool = False,
    ack: bool = False,
    psh: bool = True,
) -> PacketInfo:
    src_port = SPORT if direction == "c2s" else 80
    dst_port = 80 if direction == "c2s" else SPORT
    return PacketInfo(
        ts=ts,
        wire_len=54 + len(payload),
        classification=Classification.PARSED,
        src_ip=CLIENT if direction == "c2s" else SERVER,
        dst_ip=SERVER if direction == "c2s" else CLIENT,
        src_port=src_port,
        dst_port=dst_port,
        ip_proto=6,
        proto_name="TCP",
        tcp_flags=TcpFlags(syn=syn, ack=ack, psh=psh),
        seq=seq,
        payload_len=len(payload),
        app_payload=payload,
    )


def test_conversation_groups_both_directions() -> None:
    tracker = SessionTracker()
    conv_a = tracker.observe(tcp_pkt("c2s", seq=1001, payload=b"hello", ts=1.0))
    conv_b = tracker.observe(tcp_pkt("s2c", seq=900, payload=b"hi client", ts=1.5))
    assert conv_a is not None and conv_b is not None
    assert conv_a is conv_b
    assert conv_a.packets == 2


def test_reassembly_orders_out_of_order_segments() -> None:
    tracker = SessionTracker()
    # Feed deliberately out of order, then retransmit one segment verbatim.
    tracker.observe(tcp_pkt("c2s", seq=1002, payload=b"BB", ts=1.1))
    tracker.observe(tcp_pkt("c2s", seq=1000, payload=b"AA", ts=1.0))
    tracker.observe(tcp_pkt("c2s", seq=1004, payload=b"CC", ts=1.2))
    tracker.observe(tcp_pkt("c2s", seq=1000, payload=b"AA", ts=1.05))  # exact retransmit
    conv = tracker.ordered()[0]
    client_stream = conv.stream_for((CLIENT, SPORT))
    assert client_stream.build() == "AABBCC"
    assert client_stream.has_gaps() is False


def test_reassembly_marks_missing_segments() -> None:
    tracker = SessionTracker()
    tracker.observe(tcp_pkt("c2s", seq=1000, payload=b"AA", ts=1.0))
    tracker.observe(tcp_pkt("c2s", seq=1020, payload=b"BB", ts=1.2))
    conv = tracker.ordered()[0]
    stream = conv.stream_for((CLIENT, SPORT))
    text = stream.build()
    assert "AA" in text and "BB" in text
    assert "...18 bytes missing..." in text
    assert stream.has_gaps() is True
    assert conv.missing_segments == 1


def test_reassembled_view_renders_both_directions() -> None:
    tracker = SessionTracker()
    tracker.observe(tcp_pkt("c2s", seq=1000, payload=b"GET / HTTP/1.1\r\nHost: t\r\n\r\n", ts=1.0))
    tracker.observe(tcp_pkt("s2c", seq=2000, payload=b"HTTP/1.1 200 OK", ts=1.5))
    conv = tracker.ordered()[0]
    view = conv.reassembled_view()
    assert "client -> server" in view
    assert "server -> client" in view
    assert "GET / HTTP/1.1" in view
    assert "HTTP/1.1 200 OK" in view


def test_syn_consumes_one_sequence_number() -> None:
    tracker = SessionTracker()
    tracker.observe(tcp_pkt("c2s", seq=100, payload=b"DATA", syn=False, ack=True, ts=1.0))
    tracker.observe(tcp_pkt("c2s", seq=99, payload=b"", syn=True, ts=0.9))
    conv = tracker.ordered()[0]
    stream = conv.stream_for((CLIENT, SPORT))
    assert stream.build() == "DATA"


def test_non_transport_packets_not_grouped() -> None:
    tracker = SessionTracker()
    malformed = PacketInfo(ts=1.0, wire_len=10, classification=Classification.MALFORMED)
    tracker.observe(malformed)
    assert tracker.ordered() == []
