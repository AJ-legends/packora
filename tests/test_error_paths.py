"""Graceful-degradation tests (PRD N1/N5): capture failures produce instructions, not crashes."""

from __future__ import annotations

from packora.analysis.controller import Controller
from packora.capture.live import LiveCapture, _friendly_capture_error
from packora.capture.replay import ReplayFeed

from conftest import tcp_frame


def test_friendly_error_for_missing_npcap() -> None:
    message = _friendly_capture_error(
        RuntimeError("Sniffing and sending packets is not available at layer 2: winpcap is not installed.")
    )
    assert "https://npcap.com/" in message
    assert "--replay" in message  # points at the privilege-free alternative


def test_friendly_error_for_permission() -> None:
    message = _friendly_capture_error(OSError("Access is denied."))
    assert "Administrator" in message


def test_friendly_error_passthrough() -> None:
    assert _friendly_capture_error(ValueError("something odd")) == "something odd"


def test_feed_exception_becomes_controller_error() -> None:
    class ExplodingFeed(ReplayFeed):
        """Yields one good frame, then blows up — a stand-in for a broken capture."""

        def frames(self):  # noqa: ANN202
            yield tcp_frame()
            raise RuntimeError("pcap device exploded mid-run")

    controller = Controller(ExplodingFeed("whatever.pcap"))
    controller.run()
    assert controller.total == 1  # first packet processed despite the later failure
    assert controller.error is not None
    assert "pcap device exploded" in controller.error
    assert controller.stopped is True


def test_live_capture_reports_error_without_raising() -> None:
    """LiveCapture on a machine without Npcap: error stored, no threaded traceback."""
    capture = LiveCapture(iface="\\Device\\NPF_{00000000-0000-0000-0000-000000000000}")
    frames = list(capture.frames())
    assert frames == []  # no data expected from a broken device
    assert capture.error is not None
    assert "https://npcap.com/" in capture.error or "interface" in capture.error.lower()
