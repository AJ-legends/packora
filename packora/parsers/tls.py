"""Safe metadata-only TLS handshake parser (SNI is never decrypted content)."""

from __future__ import annotations

from dataclasses import dataclass

from packora.models.packet import TlsInfo

_VERSIONS = {b"\x03\x01": "TLS1.0", b"\x03\x02": "TLS1.1", b"\x03\x03": "TLS1.2", b"\x03\x04": "TLS1.3"}


@dataclass(frozen=True)
class TlsDecode:
    info: TlsInfo | None
    failed: bool


def parse(data: bytes) -> TlsDecode:
    """Extract a complete ClientHello/ServerHello record when one packet contains it."""
    if len(data) < 5 or data[0] != 22:
        return TlsDecode(None, False)
    record_length = int.from_bytes(data[3:5], "big")
    if record_length < 4 or len(data) < 5 + record_length:
        return TlsDecode(None, False)  # normal TCP segmentation is not malformed traffic
    record = data[5 : 5 + record_length]
    handshake_type = record[0]
    body_length = int.from_bytes(record[1:4], "big")
    if body_length + 4 > len(record):
        return TlsDecode(None, True)
    body = record[4 : 4 + body_length]
    if handshake_type == 1:
        return _client_hello(body)
    if handshake_type == 2 and len(body) >= 2:
        return TlsDecode(TlsInfo("server_hello", _VERSIONS.get(body[0:2], "TLS")), False)
    return TlsDecode(None, False)


def _client_hello(body: bytes) -> TlsDecode:
    if len(body) < 35:
        return TlsDecode(None, True)
    version = _VERSIONS.get(body[0:2], "TLS")
    cursor = 34  # version + random
    session_len = body[cursor]
    cursor += 1 + session_len
    if cursor + 2 > len(body):
        return TlsDecode(None, True)
    suites_len = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2 + suites_len
    if cursor >= len(body):
        return TlsDecode(None, True)
    compression_len = body[cursor]
    cursor += 1 + compression_len
    if cursor == len(body):
        return TlsDecode(TlsInfo("client_hello", version), False)
    if cursor + 2 > len(body):
        return TlsDecode(None, True)
    extensions_end = cursor + 2 + int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2
    if extensions_end > len(body):
        return TlsDecode(None, True)
    server_name: str | None = None
    while cursor + 4 <= extensions_end:
        extension_type = int.from_bytes(body[cursor : cursor + 2], "big")
        size = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
        cursor += 4
        if cursor + size > extensions_end:
            return TlsDecode(None, True)
        if extension_type == 0 and size >= 5:
            names = body[cursor : cursor + size]
            name_len = int.from_bytes(names[3:5], "big")
            if names[2] == 0 and 5 + name_len <= len(names):
                # SNI is an ASCII wire value. Keep hostile/non-ASCII bytes visible
                # without allowing codec-specific error modes to raise.
                server_name = names[5 : 5 + name_len].decode("ascii", errors="replace")[:253]
        cursor += size
    return TlsDecode(TlsInfo("client_hello", version, server_name), False)
