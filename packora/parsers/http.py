"""Per-packet HTTP metadata extraction (PRD F2.4).

Constraint from PRD section 8(B): this never waits on TCP reassembly — the
first payload bytes of one segment are enough to identify a request or a
response line plus a few headers.
"""

from __future__ import annotations

from dataclasses import dataclass

from packora.models.packet import HttpInfo

_REQUEST_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH")
_MAX_HEADER_LINES = 24


@dataclass(frozen=True)
class HttpDecode:
    info: HttpInfo | None
    failed: bool


def parse(data: bytes) -> HttpDecode:
    """Identify an HTTP request/response from the opening line of one segment."""
    if not data:
        return HttpDecode(None, False)  # no payload, not a failure
    first_line_end = data.find(b"\r\n")
    if first_line_end == -1:
        return HttpDecode(None, True)
    try:
        first_line = data[:first_line_end].decode("ascii")
    except UnicodeDecodeError:
        return HttpDecode(None, True)
    parts = first_line.split(" ")
    headers = {}
    for line in data[first_line_end + 2 :].split(b"\r\n")[:_MAX_HEADER_LINES]:
        if b":" not in line:
            continue
        key, _, value = line.decode("latin-1").partition(":")
        headers[key.strip().lower()] = value.strip()
    if parts and parts[0] in {m.decode() for m in _REQUEST_METHODS}:
        if len(parts) < 3:
            return HttpDecode(None, True)
        return HttpDecode(
            HttpInfo(
                kind="request",
                version=parts[2],
                method=parts[0],
                path=parts[1],
                host=headers.get("host"),
            ),
            False,
        )
    if first_line.startswith("HTTP/"):
        if len(parts) < 2:
            return HttpDecode(None, True)
        try:
            status = int(parts[1])
        except ValueError:
            return HttpDecode(None, True)
        return HttpDecode(
            HttpInfo(
                kind="response",
                version=parts[0],
                status_code=status,
                host=headers.get("host") or None,
            ),
            False,
        )
    return HttpDecode(None, False)  # simply not HTTP-looking
