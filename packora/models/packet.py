"""Neutral data models shared by parsing, analysis, and UI layers.

Per the PRD "Neutral models" contract, these classes never leak scapy types:
parsers translate captures into plain dataclasses, and tests can build them
by hand without any network access (PRD N4).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class Classification(enum.StrEnum):
    """Outcome contract for every input frame (PRD F2.1) — exactly one per packet."""

    PARSED = "parsed"
    UNSUPPORTED = "unsupported"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class DnsInfo:
    """Minimal DNS message metadata (PRD F2.3)."""

    name: str
    qtype: str
    is_response: bool
    answer_count: int
    truncated_decode: bool = False


@dataclass(frozen=True)
class HttpInfo:
    """Per-packet HTTP metadata extracted from payload bytes only (PRD F2.4)."""

    kind: str  # "request" | "response"
    version: str
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    host: str | None = None


@dataclass(frozen=True)
class TlsInfo:
    """Metadata from a complete TLS ClientHello or ServerHello record."""

    kind: str  # "client_hello" | "server_hello"
    version: str
    server_name: str | None = None


@dataclass(frozen=True)
class DhcpInfo:
    """Safe DHCP metadata; no client identifiers or payload are retained."""

    message_type: str
    hostname: str | None = None
    requested_ip: str | None = None


@dataclass(frozen=True)
class NtpInfo:
    """Basic NTP header metadata for UDP/123 traffic."""

    version: int
    mode: str
    stratum: int


@dataclass(frozen=True)
class TcpFlags:
    """Decoded TCP control-flag bits."""

    fin: bool = False
    syn: bool = False
    rst: bool = False
    psh: bool = False
    ack: bool = False
    urg: bool = False

    def as_str(self) -> str:
        parts = []
        for letter, set_flag in (
            ("F", self.fin),
            ("S", self.syn),
            ("R", self.rst),
            ("P", self.psh),
            ("A", self.ack),
            ("U", self.urg),
        ):
            if set_flag:
                parts.append(letter)
        return ",".join(parts) if parts else "-"

    @property
    def is_syn_without_ack(self) -> bool:
        """The handshake-detection primitive: probe SYNs not carrying ACK (PRD F4.1)."""
        return self.syn and not self.ack

    @property
    def is_synack(self) -> bool:
        return self.syn and self.ack


@dataclass
class PacketInfo:
    """One analyzed packet, whatever its classification. This is the currency of the app."""

    ts: float
    wire_len: int
    classification: Classification
    src_mac: str | None = None
    dst_mac: str | None = None
    ethertype: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_proto: int | None = None
    proto_name: str | None = None  # "TCP", "UDP", "DNS" display hint
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: TcpFlags | None = None
    seq: int | None = None
    payload_len: int = 0
    dns: DnsInfo | None = None
    http: HttpInfo | None = None
    tls: TlsInfo | None = None
    dhcp: DhcpInfo | None = None
    ntp: NtpInfo | None = None
    arp_sender_ip: str | None = None
    arp_sender_mac: str | None = None
    arp_target_ip: str | None = None
    # Exactly one of these is set for non-parsed packets (PRD F2.1):
    unsupported_protocol: str | None = None  # e.g. "unknown ethertype 0x8100"
    malformed_reason: str | None = None  # e.g. "truncated IPv4 header"
    notes: list[str] = field(default_factory=list)
    app_payload: bytes = b""  # transport payload bytes (TCP/UDP), for stream view
    payload_preview: str = ""

    @property
    def is_broken(self) -> bool:
        return self.classification is not Classification.PARSED

    @property
    def is_flow_start(self) -> bool:
        """SYN-without-ACK: the handshake-detection primitive (PRD F4.1)."""
        return bool(self.tcp_flags and self.tcp_flags.is_syn_without_ack)

    def one_liner(self) -> str:
        """Human scanning-readable per-packet summary (PRD F2.2)."""
        stamp = datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")
        if self.classification is Classification.MALFORMED:
            return f"{stamp} len={self.wire_len} MALFORMED: {self.malformed_reason}"
        if self.classification is Classification.UNSUPPORTED:
            return f"{stamp} len={self.wire_len} UNSUPPORTED: {self.unsupported_protocol}"
        src = self._ip_port(self.src_ip, self.src_port)
        dst = self._ip_port(self.dst_ip, self.dst_port)
        head = f"{stamp} len={self.wire_len} {src} -> {dst}"
        parts = []
        if self.proto_name:
            parts.append(self.proto_name)
        if self.tcp_flags and self.tcp_flags.as_str() != "-":
            parts.append(f"flags={self.tcp_flags.as_str()}")
        if self.dns is not None:
            direction = (
                f"response: {self.dns.answer_count} answer(s)" if self.dns.is_response else "query"
            )
            tr_note = " [name compressed]" if self.dns.truncated_decode else ""
            parts.append(f"DNS {direction} {self.dns.qtype} {self.dns.name}{tr_note}".rstrip())
        if self.http is not None:
            if self.http.kind == "request":
                parts.append(f"HTTP {self.http.method} {self.http.path} ({self.http.host})")
            else:
                parts.append(f"HTTP {self.http.status_code}")
        if self.tls is not None:
            sni = f" SNI={self.tls.server_name}" if self.tls.server_name else ""
            parts.append(f"TLS {self.tls.kind} {self.tls.version}{sni}")
        if self.dhcp is not None:
            hostname = f" host={self.dhcp.hostname}" if self.dhcp.hostname else ""
            parts.append(f"DHCP {self.dhcp.message_type}{hostname}")
        if self.ntp is not None:
            parts.append(f"NTP {self.ntp.mode} v{self.ntp.version} stratum={self.ntp.stratum}")
        for note in self.notes:
            parts.append(f"note: {note}")
        return head + (" " + " ".join(parts) if parts else "")

    @staticmethod
    def _ip_port(ip: str | None, port: int | None) -> str:
        if ip is None:
            return "?"
        return f"{ip}:{port}" if port is not None else ip
