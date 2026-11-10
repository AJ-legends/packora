"""UI smoke test: real Textual app, headless pilot — catches API drift (PRD N6)."""

from __future__ import annotations

import asyncio

import pytest
from packora.analysis.controller import Controller
from packora.capture.replay import ReplayFeed
from packora.ui.app import HelpScreen, PacketDetailScreen, PackoraApp, SessionsScreen
from textual.widgets import DataTable, Input, Static

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


async def test_stream_search_filters_conversation_lines(controller_with_demo) -> None:  # type: ignore[no-untyped-def]
    app = PackoraApp(controller_with_demo, refresh_hz=10)
    try:
        async with app.run_test(size=(110, 30)) as pilot:
            await _wait_for_packets(controller_with_demo)
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause()
            sessions = app.screen
            http_index = next(
                index
                for index, conversation in enumerate(controller_with_demo.sessions.ordered())
                if 80 in {conversation.client[1], conversation.server[1]}
            )
            sessions._open_stream(http_index)
            sessions.action_search_stream()
            search = sessions.query_one("#stream-search", Input)
            assert search.display is True
            await pilot.press("g", "e", "t")
            await pilot.pause()
            stream_view = sessions.query_one("#stream-view", Static)
            assert "GET /index.html HTTP/1.1" in str(stream_view.renderable)
            status = sessions.query_one("#stream-search-status", Static)
            assert "matching line" in str(status.renderable)
    finally:
        controller_with_demo.stop_thread()


async def test_session_search_and_packet_detail(controller_with_demo) -> None:  # type: ignore[no-untyped-def]
    app = PackoraApp(controller_with_demo, refresh_hz=10)
    try:
        async with app.run_test(size=(110, 30)) as pilot:
            await _wait_for_packets(controller_with_demo)
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause()
            sessions = app.screen
            session_search = sessions.query_one("#session-search", Input)
            session_search.value = "50001"
            await pilot.pause()
            table = sessions.query_one("#sessions", DataTable)
            assert table.row_count == 1
            await pilot.press("q")
            await pilot.pause()
            app._tick()
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, PacketDetailScreen)
            detail = app.screen.query_one("#packet-detail", Static)
            assert "PACKET DETAIL" in str(detail.renderable)
    finally:
        controller_with_demo.stop_thread()
