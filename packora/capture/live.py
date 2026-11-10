"""Live capture via scapy (PRD F1.1, F1.2, F1.4).

scapy stays inside capture/ by contract; downstream code only sees `Frame`s.
A sniff runs in a daemon thread pushing frames into a bounded queue, so the
caller gets a normal generator it can stop or abandon at any time.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Iterator
from typing import Any

from packora.capture.base import Frame

_UNKNOWN_IP = "0.0.0.0"


def _install_scapy_noise_filter() -> None:
    """Silence scapy's import-time 'No libpcap provider' warning.

    Packora reports a missing Npcap/libpcap through its own friendly error
    (PRD N1), so this duplicate raw warning is pure noise. All other scapy
    warnings stay visible. Must run before scapy is first imported; loggers
    are singletons, so the filter attaches to the same logger scapy uses.
    """
    logging.getLogger("scapy.loading").addFilter(
        lambda record: "No libpcap provider available" not in record.getMessage()
    )


_install_scapy_noise_filter()


def list_interfaces() -> list[tuple[str, str]]:
    """[(name, ip)] for CLI/TUI display (PRD F1.1). Best-effort: never raises."""
    try:
        from scapy.all import get_if_addr, get_if_list

        return [(name, get_if_addr(name) or _UNKNOWN_IP) for name in get_if_list()]
    except Exception:  # noqa: BLE001 - missing Npcap/libpcap must degrade (PRD N5)
        return []


class LiveCapture:
    """Iterable source of live frames; stop via `stop()` or by closing the generator."""

    def __init__(
        self,
        iface: str | None = None,
        bpf_filter: str | None = None,
        count: int | None = None,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count
        self._stop = threading.Event()
        #: Populated when the capture thread fails (PRD N1: informative, no tracebacks).
        self.error: str | None = None

    @property
    def description(self) -> str:
        target = self.iface or "default interface"
        extra = f" filter={self.bpf_filter!r}" if self.bpf_filter else ""
        return f"live:{target}{extra}"

    def stop(self) -> None:
        self._stop.set()

    def frames(self) -> Iterator[Frame]:
        from scapy.all import sniff

        capture = self
        q: queue.Queue[Frame | None] = queue.Queue(maxsize=512)

        def prn(pkt: Any) -> None:
            if capture._stop.is_set():
                return
            try:
                frame = Frame(ts=float(getattr(pkt, "time", 0)), raw=bytes(pkt))
            except Exception:  # noqa: BLE001 - a bad callback packet must not kill sniff
                return
            try:
                q.put(frame, timeout=1)
            except queue.Full:
                pass  # consumer stalled: drop instead of blocking the capture thread

        def run_sniff() -> None:
            try:
                kwargs: dict[str, Any] = {"store": False}
                if capture.iface:
                    kwargs["iface"] = capture.iface
                if capture.bpf_filter:
                    kwargs["filter"] = capture.bpf_filter
                if capture.count:
                    kwargs["count"] = capture.count
                if not kwargs.get("filter"):
                    kwargs.pop("filter", None)

                def stop_filter(_pkt: Any) -> Any:
                    return capture._stop.is_set()

                kwargs["stop_filter"] = stop_filter
                kwargs["prn"] = prn
                sniff(**kwargs)
            except Exception as exc:  # noqa: BLE001 - capture failures are reported, not raised
                capture.error = _friendly_capture_error(exc)
            finally:
                q.put(None)

        worker = threading.Thread(target=run_sniff, daemon=True)
        worker.start()
        try:
            while True:
                item = q.get()
                if item is None:
                    break
                yield item
        finally:
            capture.stop()
            worker.join(timeout=3)


def _friendly_capture_error(exc: Exception) -> str:
    """Turn scapy capture failures into plain instructions (PRD N5)."""
    text = str(exc)
    lowered = (text or "").lower()
    if "winpcap" in lowered or "layer 2" in lowered:
        return (
            "Npcap is not installed (or lacks WinPcap API support), so live capture "
            "cannot work. Fix: install Npcap from https://npcap.com/ and run Packora "
            "from an Administrator terminal. Replay mode (--replay FILE.pcap) needs "
            "neither Npcap nor admin rights."
        )
    if "permission" in lowered or "access is denied" in lowered:
        return "Capture needs elevated rights: Administrator on Windows (Npcap) or root on Linux."
    if "no devic" in lowered or "invalid" in lowered or "iface" in lowered:
        return f"Could not open the capture interface ({text}). Check the name with --list-interfaces."
    return text
