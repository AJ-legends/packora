"""NTP header metadata parsing for UDP/123."""

from __future__ import annotations

from packora.models.packet import NtpInfo


def parse(data: bytes) -> NtpInfo | None:
    if len(data) < 48:
        return None
    first = data[0]
    version = (first >> 3) & 0x07
    mode_value = first & 0x07
    if version == 0:
        return None
    mode = {1: "symmetric_active", 2: "symmetric_passive", 3: "client", 4: "server", 5: "broadcast"}.get(mode_value, f"mode_{mode_value}")
    return NtpInfo(version=version, mode=mode, stratum=data[1])
