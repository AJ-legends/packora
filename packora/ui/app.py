"""Packora terminal UI (PRD F5).

Design intent: a first-time user understands the screen without reading docs —
keyboard navigation, visible focus hints, `?` help overlay, no empty panels.
"""

from __future__ import annotations

from datetime import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from packora.analysis.controller import Controller
from packora.analysis.sessions import render_conversation_table
from packora.models.packet import PacketInfo

MAX_REFRESH_ROWS = 120

HELP_TEXT = """\
[bold]Packora[/bold] — educational packet analyzer. Authorized networks only.

[table]Key        Action
────────────────────────────────────────────
q          quit (run summary follows)
/          focus the live packet filter (updates as you type, Esc clears)
?          this help
p          open the sessions view (TCP conversations)
enter      (sessions view) open the reassembled stream[/table]

The dashboard is designed for scanning: packet outcome is always shown first,
the filter is always available, and the right side explains capture state,
protocol mix, rate, and alerts. Empty views always explain why they are empty.
"""


class HelpScreen(ModalScreen):
    """`?` overlay: every shortcut and panel explained in one place (PRD F5.3)."""

    CSS = """
    HelpScreen { align: center middle; }
    HelpScreen > Static {
        width: 80%; padding: 1 2; border: solid $accent; background: $surface;
    }
    """

    BINDINGS = [("q", "dismiss_screen", "Close"), ("?", "dismiss_screen", "Close")]

    def compose(self) -> ComposeResult:
        yield Static(HELP_TEXT, markup=True)

    def action_dismiss_screen(self) -> None:
        self.dismiss()


class SessionsScreen(Screen):
    """Conversation table; Enter opens the reassembled stream (PRD F5.2 / F3.3)."""

    CSS = """
    SessionsScreen { padding: 0 1; }
    SessionsScreen #stream-view {
        display: none;
        height: 1fr;
        border: solid $accent;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("q", "back", "Back"),
        ("escape", "back", "Back"),
    ]

    def __init__(self, controller: Controller) -> None:
        super().__init__()
        self.controller = controller

    def compose(self) -> ComposeResult:
        table: DataTable = DataTable(id="sessions")
        table.cursor_type = "row"
        yield table
        yield Static("", id="stream-view")

    # Sessions view (PRD F5.2): the table is focused by default; Enter reaches us
    # as DataTable.RowSelected (the table consumes the key itself).
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._open_stream(event.cursor_row)

    def on_mount(self) -> None:
        table = self.query_one("#sessions", DataTable)
        table.clear(columns=True)
        table.add_columns("#", "proto", "client", "server", "pkts", "bytes", "gaps")
        conversations = self.controller.sessions.ordered()
        for row in render_conversation_table(conversations):
            table.add_row(*[str(cell) for cell in row])
        if not conversations:
            table.add_row("", "-", "-", "-", "no conversations yet", "", "")
        stream_view = self.query_one("#stream-view", Static)
        stream_view.display = False
        table.focus()

    def action_open_stream(self) -> None:
        table = self.query_one("#sessions", DataTable)
        self._open_stream(table.cursor_row)

    def _open_stream(self, cursor_row: int | None) -> None:
        conversations = self.controller.sessions.ordered()
        if cursor_row is None or cursor_row >= len(conversations):
            return
        conv = conversations[cursor_row]
        stream_view = self.query_one("#stream-view", Static)
        stream_view.update(conv.reassembled_view())
        self.query_one("#sessions", DataTable).display = False
        stream_view.display = True

    def action_back(self) -> None:
        self.dismiss()


def _bar_chart(mix: list[tuple[str, int]], total: int, width: int = 32) -> str:
    """ASCII bar share per bucket; colors plus ratios in the caption (PRD F5.1)."""
    if total == 0:
        return "no packets yet — waiting for capture"
    lines = []
    for name, count in mix:
        share = count / max(total, 1)
        filled = int(round(share * width))
        bar = "#" * max(1, filled) if count else ""
        lines.append(f"{name:<12}{count:>7} {bar}")
    return "\n".join(lines)


class PackoraApp(App):
    """Main dashboard (PRD F5.1 target layout)."""

    TITLE = "Packora"
    SUB_TITLE = "educational packet analyzer"

    CSS = """
    #main { height: 1fr; padding: 0 1; }
    #left { width: 66%; min-width: 58; }
    #right { width: 1fr; }
    #packet-heading { padding: 0 1; text-style: bold; color: $accent; }
    #filter { margin: 0 0 1 0; }
    #packets { height: 1fr; border: solid $accent; }
    #capture-status { border: solid $primary; padding: 0 1; height: auto; margin: 0 0 1 1; }
    #protomix { border: solid $accent; padding: 0 1; height: 1fr; margin: 0 0 1 1; }
    #alerts { border: solid $warning; padding: 0 1; height: 1fr; margin: 0 0 1 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("/", "show_filter", "Filter", show=True),
        Binding("?", "help", "Help", show=True),
        Binding("p", "sessions", "Sessions", show=True),
        Binding("escape", "escape", "Back/Clear", show=False),
    ]

    def __init__(self, controller: Controller, refresh_hz: float = 5.0) -> None:
        super().__init__()
        self.controller = controller
        self._refresh_hz = refresh_hz
        self.filter_text = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Static("LIVE PACKETS", id="packet-heading")
                yield Input(placeholder="Filter packets: protocol, address, port, DNS name, HTTP path...", id="filter")
                yield DataTable(id="packets")
            with Vertical(id="right"):
                yield Static("Preparing capture...", id="capture-status")
                yield Static("Protocol mix\n\nWaiting for packets...", id="protomix")
                yield Static("Alerts\n\nNo alerts raised yet.", id="alerts")
        yield Footer()

    def on_mount(self) -> None:
        self.table = self.query_one("#packets", DataTable)
        self._protomix = self.query_one("#protomix", Static)
        self._alerts = self.query_one("#alerts", Static)
        self._capture_status = self.query_one("#capture-status", Static)
        self._filter = self.query_one("#filter", Input)
        self.table.cursor_type = "row"
        self.table.zebra_stripes = True
        self.table.add_columns("time", "outcome", "protocol", "source", "destination", "summary")
        self.set_interval(1 / self._refresh_hz, self._tick)
        self.set_interval(0.5, self._start_capture_once)
        self.table.focus()

    def _start_capture_once(self) -> None:
        if not self.controller.stopped and self.controller._thread is None:
            self.controller.start_thread()

    def _tick(self) -> None:
        """One UI batch: drain shared state, repaint widgets (N3)."""
        state = self.controller.snapshot()
        phase = "complete" if state.stopped else "capturing"
        self.sub_title = f"{phase} | {state.description} | {state.total} packets | {state.rate:.0f} pkt/s"
        if state.error:
            self._capture_status.update(f"CAPTURE NEEDS ATTENTION\n\n{state.error}\n\nUse replay mode to inspect a PCAP without capture privileges.")
            self._alerts.update("Alerts\n\nCapture stopped before alerts could be evaluated.")
            return
        self._update_packets(state.recent)
        mix = _bar_chart(state.mix, state.total)
        self._protomix.update(f"PROTOCOL MIX\n\n{mix}")
        filter_state = f"Filter: {self.filter_text}" if self.filter_text else "Filter: showing all recent packets"
        self._capture_status.update(
            f"CAPTURE STATUS\n\n{phase.upper()} - {state.total} packets - {state.rate:.0f} pkt/s\n{filter_state}\n\n/ filter   ? help   p sessions   q quit"
        )
        alerts = state.alerts
        if alerts:
            alert_lines = "\n".join(a.one_liner() for a in alerts[-12:])
            self._alerts.update(f"ALERTS ({len(alerts)} recent)\n\n{alert_lines}")
        else:
            self._alerts.update("ALERTS\n\nNo alerts raised. This is normal for benign traffic.")

    def _update_packets(self, recent: list[PacketInfo]) -> None:
        """Repaint the packet table from the thread-shared tail, filtered by needle (F5.4)."""
        table = self.table
        needle = self.filter_text.lower()
        try:
            table.clear(columns=False)
        except Exception:  # noqa: BLE001 - never let a repaint tick kill the UI
            return
        rows = []
        for pkt in reversed(recent[-MAX_REFRESH_ROWS:]):
            line = pkt.one_liner()
            if needle and needle not in line.lower():
                continue
            rows.append(
                (
                    datetime.fromtimestamp(pkt.ts).strftime("%H:%M:%S"),
                    pkt.classification.value.upper(),
                    pkt.proto_name or "NETWORK",
                    pkt.src_ip or "",
                    pkt.dst_ip or "",
                    line,
                )
            )
        if not rows:
            empty = f"No packets match filter: {self.filter_text}" if needle else "Waiting for packets..."
            table.add_row("", "", "", "", "", empty)
            return
        for row in rows[:MAX_REFRESH_ROWS]:
            table.add_row(*row)

    def action_show_filter(self) -> None:
        self._filter.focus()

    def action_escape(self) -> None:
        if self._filter.has_focus:
            self.filter_text = ""
            self._filter.value = ""
            self.table.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.control.id == "filter":
            self.filter_text = event.value.strip()
            self._update_packets(list(self.controller.recent))
            self.table.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.control.id == "filter":
            self.filter_text = event.value.strip()
            self._update_packets(list(self.controller.recent))

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_sessions(self) -> None:
        self.push_screen(SessionsScreen(self.controller))
