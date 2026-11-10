"""UI smoke test: real Textual app, headless pilot — catches API drift (PRD N6)."""

from __future__ import annotations

import asyncio

import pytest
from packora.analysis.controller import Controller
from packora.capture.replay import ReplayFeed
from packora.ui.app import HelpScreen, PackoraApp, SessionsScreen
from textual.widgets import DataTable, Static

from conftest import demo_pcap_path

# scapy's cold import inside the replay thread can take several seconds (PRD N3 note).
MAX_WAIT_S = 20.0


async def _wait_for_packets(controller: Controller) -> None:
    waited = 0.0
    while controller.total == 0 and waited < MAX_WAIT_S:
        await asyncio.sleep(0.2)
        waited += 0.2
    assert controller.total > 0, "the replay thread produced no packets"


@pytest.fixture
def controller_with_demo() -> Controller:
    controller = Controller(ReplayFeed(str(demo_pcap_path())))
    controller.start_thread()
    return controller


async def test_dashboard_renders_packets_and_stats(controller_with_demo) -> None:  # type: ignore[no-untyped-def]
    app = PackoraApp(controller_with_demo, refresh_hz=10)
    try:
        async with app.run_test(size=(110, 30)) as pilot:
            await _wait_for_packets(controller_with_demo)
            await pilot.pause()
            app._tick()  # force one repaint with the packets guaranteed present
            table = app.query_one("#packets", DataTable)
            assert table.row_count >= 2, "packet table should show real packets, not the empty placeholder"
            mix = str(app.query_one("#protomix", Static).renderable)
            assert "protocol mix" in mix.lower()
    finally:
        controller_with_demo.stop_thread()


async def test_help_overlay_and_sessions_screen(controller_with_demo) -> None:  # type: ignore[no-untyped-def]
    app = PackoraApp(controller_with_demo, refresh_hz=10)
    try:
        async with app.run_test(size=(110, 30)) as pilot:
            await _wait_for_packets(controller_with_demo)
            await pilot.pause()
            await pilot.press("?")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)
            await pilot.press("?")  # close overlay
            await pilot.pause()
            assert not isinstance(app.screen, HelpScreen)
            await pilot.press("p")
            await pilot.pause()
            assert isinstance(app.screen, SessionsScreen)
            await pilot.press("q")  # back from the sessions view
            await pilot.pause()
            assert not isinstance(app.screen, SessionsScreen)
    finally:
        controller_with_demo.stop_thread()


async def test_stream_view_opens_on_enter(controller_with_demo) -> None:  # type: ignore[no-untyped-def]
    app = PackoraApp(controller_with_demo, refresh_hz=10)
    try:
        async with app.run_test(size=(110, 30)) as pilot:
            await _wait_for_packets(controller_with_demo)
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause()
            assert isinstance(app.screen, SessionsScreen)
            await pilot.press("enter")
            await pilot.pause()
            sessions = app.screen
            stream_view = sessions.query_one("#stream-view", Static)
            assert stream_view.display is True
            assert str(stream_view.renderable) not in ("",)
    finally:
        controller_with_demo.stop_thread()
