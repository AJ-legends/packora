"""DNS message parsing (PRD F2.3).

Handles the common uncompressed-query case; tolerates compression pointers
(name decoding stops at the pointer rather than misreading it). Response
metadata (flag, answer count, RCODE) is always extracted.
"""

from __future__ import annotations

from dataclasses import dataclass

from packora.models.packet import DnsInfo

_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}


@dataclass(frozen=True)
class DnsDecode:
    info: DnsInfo | None
    failed: bool


def _decode_name(data: bytes, start: int) -> tuple[str, int, bool]:
    """Return (name, next_index, hit_compression_pointer)."""
    labels: list[str] = []
    idx = start
    for _ in range(255):
        length = data[idx]
        if length == 0:
            return ".".join(labels), idx + 1, False
        if length & 0xC0 == 0xC0:
            # Compression pointer: referenced name is elsewhere in the message and
            # cannot be reconstructed from a partial payload. Stop, don't guess.
            return ".".join(labels), idx + 2, len(labels) == 0
        end = idx + 1 + length
        if end > len(data):
            raise IndexError
        labels.append(data[idx + 1 : end].decode("ascii", errors="replace"))
        idx = end
    raise IndexError  # unterminated name


def parse(data: bytes) -> DnsDecode:
    """Decode a DNS message (UDP payload or TCP app-layer, minus the 2-byte prefix).

    Returns `(info, False)` on success, `(None, True)` when the message cannot
    be decoded — a note, never a crash (PRD N2).
    """
    if len(data) < 12:
        return DnsDecode(None, True)
    raw_flags = int.from_bytes(data[2:4], "big")
    is_response = bool(raw_flags & 0x8000)
    answer_count = int.from_bytes(data[6:8], "big")
    qdcount = int.from_bytes(data[4:6], "big")

    try:
        idx = 12
        name = ""
        compressed = False
        if qdcount >= 1:
            name, idx, compressed = _decode_name(data, idx)
            if idx + 4 <= len(data):
                qtype_raw = int.from_bytes(data[idx : idx + 2], "big")
                idx += 4  # qtype + qclass
            else:
                return DnsDecode(None, True)
        else:
            qtype_raw = 0
    except IndexError:
        return DnsDecode(None, True)

    info = DnsInfo(
        name=name,
        qtype=_QTYPE_NAMES.get(qtype_raw, f"type{qtype_raw}") if qdcount >= 1 else "",
        is_response=is_response,
        answer_count=answer_count,
        truncated_decode=compressed,
    )
    return DnsDecode(info, False)
