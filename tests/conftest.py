"""Synthetic frame builders for tests — pure bytes, no scapy, no network (PRD N4)."""

from __future__ import annotations

from pathlib import Path

from packora.capture.base import Frame
from packora.models.packet import (
    Classification,
    DnsInfo,
    HttpInfo,
    PacketInfo,
    TcpFlags,
)

# TCP control-bit flags (byte 13 of the TCP header)
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

REPO_ROOT = Path(__file__).resolve().parents[1]


def mac_bytes(addr: str) -> bytes:
    return bytes.fromhex(addr.replace(":", ""))


def eth_header(src: str = "02:00:00:00:00:01", dst: str = "02:00:00:00:00:02", ethertype: int = 0x0800) -> bytes:
    return mac_bytes(dst) + mac_bytes(src) + ethertype.to_bytes(2, "big")


def ipv4_header(payload: bytes, src: str = "10.0.0.5", dst: str = "10.0.0.1", proto: int = 6) -> bytes:
    total_len = 20 + len(payload)
    return (
        bytes([0x45, 0x00])
        + total_len.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"  # id + flags/frag
        + bytes([64, proto, 0x00, 0x00])
        + bytes(int(x) for x in src.split("."))
        + bytes(int(x) for x in dst.split("."))
    )


def tcp_header(
    sport: int,
    dport: int,
    seq: int,
    flags: int = 0x02,
    payload: bytes = b"",
    ack: int = 0,
) -> bytes:
    return (
        sport.to_bytes(2, "big")
        + dport.to_bytes(2, "big")
        + seq.to_bytes(4, "big")
        + ack.to_bytes(4, "big")
        + bytes([0x50, flags])
        + (8192).to_bytes(2, "big")
        + (0).to_bytes(2, "big")  # checksum placeholder; NOT validated by parsers
        + (0).to_bytes(2, "big")
        + payload
    )


def udp_header(sport: int, dport: int, payload: bytes) -> bytes:
    return (
        sport.to_bytes(2, "big")
        + dport.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + payload
    )


def dns_query_payload(qname: str = "example.test", response: bool = False, answers: int = 0) -> bytes:
    flags = 0x8180 if response else 0x0100
    # DNS wire format: length-prefixed labels + terminating zero byte
    name = b"".join(
        bytes([len(label)]) + label.encode() for label in qname.split(".")
    ) + b"\x00"
    return (
        (0x1234).to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + (0 if response else 1).to_bytes(2, "big")
        + answers.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + name
        + (1).to_bytes(2, "big")  # qtype A
        + (1).to_bytes(2, "big")  # qclass IN
    )


def frame(
    ip_payload: bytes,
    src: str = "10.0.0.5",
    dst: str = "10.0.0.1",
    proto: int = 6,
    ts: float = 1700000100.0,
    ethertype: int = 0x0800,
    src_mac: str = "02:00:00:00:00:01",
) -> Frame:
    eth = eth_header(src=src_mac, dst="02:00:00:00:00:02", ethertype=ethertype)
    iph = ipv4_header(ip_payload, src=src, dst=dst, proto=proto)
    if ethertype == 0x0800:
        return Frame(ts=ts, raw=eth + iph + ip_payload)
    # Non-IP ethertypes: the bytes go straight into the frame body.
    return Frame(ts=ts, raw=eth + ip_payload)


def tcp_frame(
    sport: int = 40000,
    dport: int = 80,
    seq: int = 1000,
    flags: int = 0x02,
    payload: bytes = b"",
    **overrides: object,
) -> Frame:
    defaults = {"src": "10.0.0.5", "dst": "10.0.0.1", "proto": 6, "ts": 1700000100.0}
    defaults.update(overrides)
    return frame(tcp_header(sport, dport, seq, flags, payload), **defaults)  # type: ignore[arg-type]


def udp_frame(sport: int = 40000, dport: int = 53, payload: bytes = b"", **overrides: object) -> Frame:
    defaults = {"src": "10.0.0.5", "dst": "10.0.0.1", "proto": 17, "ts": 1700000100.0}
    defaults.update(overrides)
    return frame(udp_header(sport, dport, payload), **defaults)  # type: ignore[arg-type]


def packet(
    classification: Classification = Classification.PARSED,
    ts: float = 1700000100.0,
    src_ip: str | None = "10.0.0.5",
    dst_ip: str | None = "10.0.0.1",
    src_port: int = 40000,
    dst_port: int = 80,
    flags: TcpFlags | None = None,
    seq: int = 1000,
    payload: bytes = b"",
    wire_len: int = 60,
    ip_proto: int = 6,
    proto_name: str | None = "TCP",
    dns: DnsInfo | None = None,
    http: HttpInfo | None = None,
    raw: bytes = b"",  # unused in tests
    **extra: object,
) -> PacketInfo:
    return PacketInfo(
        ts=ts,
        wire_len=wire_len,
        classification=classification,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_proto=ip_proto,
        proto_name=proto_name,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        seq=seq,
        payload_len=len(payload),
        app_payload=payload,
        dns=dns,
        http=http,
        **extra,  # type: ignore[arg-type]
    )


def syn_packet(dst_port: int = 80, ts: float = 1.0, src_ip: str = "10.0.0.9", dst_ip: str = "10.0.1.1") -> PacketInfo:
    return packet(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        flags=TcpFlags(syn=True),
        seq=1,
        payload=b"",
    )


def demo_pcap_path() -> Path:
    """The committed sample; regenerate it from its generator when missing."""
    path = REPO_ROOT / "samples" / "demo.pcap"
    if not path.exists():  # pragma: no cover - safety net for fresh checkouts
        sys_path = str(REPO_ROOT / "samples")
        if sys_path not in __import__("sys").path:
            __import__("sys").path.insert(0, sys_path)
        import generate_demo

        generate_demo.main(path)
    return path
