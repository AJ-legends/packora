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
enter      open selected packet detail or conversation stream
/          search packet rows, sessions, or an open stream
/          (stream view) search conversation text; Enter exits search[/table]

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
    SessionsScreen #stream-search, SessionsScreen #stream-search-status {
        display: none;
    }
    SessionsScreen #stream-search.visible, SessionsScreen #stream-search-status.visible {
        display: block;
    }
    SessionsScreen #stream-search-status { padding: 0 1; color: $text-muted; }
    SessionsScreen #session-search { margin: 0 0 1 0; }
    PacketDetailScreen { align: center middle; }
    PacketDetailScreen #packet-detail {
        width: 90%; height: 85%; overflow: auto; border: solid $accent;
        padding: 1 2; background: $surface;
    }
    """

    BINDINGS = [
        ("q", "back", "Back"),
        ("escape", "back", "Back"),
        ("slash", "search_stream", "Find"),
    ]

    def __init__(self, controller: Controller) -> None:
        super().__init__()
        self.controller = controller
        self._stream_text = ""
        self._session_search_text = ""

    def compose(self) -> ComposeResult:
        table: DataTable = DataTable(id="sessions")
        table.cursor_type = "row"
        yield Input(placeholder="Filter conversations: endpoint, port, protocol...", id="session-search")
        yield table
        yield Input(placeholder="Find text in this conversation...", id="stream-search")
        yield Static("", id="stream-search-status")
        yield Static("", id="stream-view")

    # Sessions view (PRD F5.2): the table is focused by default; Enter reaches us
    # as DataTable.RowSelected (the table consumes the key itself).
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._open_stream(event.cursor_row)

    def on_mount(self) -> None:
        table = self.query_one("#sessions", DataTable)
        self._session_search = self.query_one("#session-search", Input)
        self._render_sessions()
        stream_view = self.query_one("#stream-view", Static)
        self._search = self.query_one("#stream-search", Input)
        self._search_status = self.query_one("#stream-search-status", Static)
        stream_view.display = False
        table.focus()

    def action_open_stream(self) -> None:
        table = self.query_one("#sessions", DataTable)
        self._open_stream(table.cursor_row)

    def _open_stream(self, cursor_row: int | None) -> None:
        conversations = self._filtered_conversations()
        if cursor_row is None or cursor_row >= len(conversations):
            return
        conv = conversations[cursor_row]
        stream_view = self.query_one("#stream-view", Static)
        self._stream_text = conv.reassembled_view()
        self._render_stream_search()
        self.query_one("#sessions", DataTable).display = False
        stream_view.display = True

    def _filtered_conversations(self):
        needle = self._session_search_text.lower()
        conversations = self.controller.sessions.ordered()
        if not needle:
            return conversations
        return [
            conversation
            for conversation in conversations
            if needle
            in " ".join(
                (
                    conversation.proto,
                    f"{conversation.client[0]}:{conversation.client[1]}",
                    f"{conversation.server[0]}:{conversation.server[1]}",
                )
            ).lower()
        ]

    def _render_sessions(self) -> None:
        table = self.query_one("#sessions", DataTable)
        table.clear(columns=True)
        table.add_columns("#", "proto", "client", "server", "pkts", "bytes", "gaps")
        conversations = self._filtered_conversations()
        for row in render_conversation_table(conversations):
            table.add_row(*[str(cell) for cell in row])
        if not conversations:
            message = "no conversations match filter" if self._session_search_text else "no conversations yet"
            table.add_row("", "-", "-", "-", message, "", "")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.control.id == "session-search":
            self._session_search_text = event.value.strip()
            self._render_sessions()
            return
        if event.control.id == "stream-search":
            self._render_stream_search()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.control.id == "session-search":
            self.query_one("#sessions", DataTable).focus()
            return
        if event.control.id == "stream-search":
            self._search.blur()

    def action_search_stream(self) -> None:
        """Focus a visible, non-destructive search field for the open stream."""
        if not self._stream_text:
            return
        self._search.add_class("visible")
        self._search_status.add_class("visible")
        self._search.focus()

    def _render_stream_search(self) -> None:
        """Show matching stream lines live without mutating the reconstructed evidence."""
        needle = self._search.value.strip().lower() if hasattr(self, "_search") else ""
        stream_view = self.query_one("#stream-view", Static)
        if not needle:
            stream_view.update(self._stream_text)
            if hasattr(self, "_search_status"):
                self._search_status.update("Type to filter conversation lines. Enter returns to navigation.")
            return
        matching_lines = [line for line in self._stream_text.splitlines() if needle in line.lower()]
        stream_view.update("\n".join(matching_lines) if matching_lines else "No matching conversation lines.")
        self._search_status.update(f"{len(matching_lines)} matching line(s) for: {self._search.value}")

    def action_back(self) -> None:
        self.dismiss()


class PacketDetailScreen(ModalScreen):
    """Readable packet inspection without exposing raw capture-library objects."""

    BINDINGS = [("q", "dismiss_screen", "Close"), ("escape", "dismiss_screen", "Close")]

    def __init__(self, pkt: PacketInfo) -> None:
        super().__init__()
        self.pkt = pkt

    def compose(self) -> ComposeResult:
        yield Static(_packet_detail_text(self.pkt), id="packet-detail")

    def action_dismiss_screen(self) -> None:
        self.dismiss()


def _packet_detail_text(pkt: PacketInfo) -> str:
    """A scan-friendly field sheet for one packet."""
    lines = [
        "PACKET DETAIL",
        "=" * 60,
        f"time           {datetime.fromtimestamp(pkt.ts).isoformat(sep=' ', timespec='milliseconds')}",
        f"outcome        {pkt.classification.value}",
        f"wire length    {pkt.wire_len} bytes",
        f"protocol       {pkt.proto_name or 'network'}",
        f"source         {pkt._ip_port(pkt.src_ip, pkt.src_port)}",
        f"destination    {pkt._ip_port(pkt.dst_ip, pkt.dst_port)}",
    ]
    if pkt.tcp_flags:
        lines.append(f"TCP flags      {pkt.tcp_flags.as_str()}  seq={pkt.seq}")
    if pkt.dns:
        lines.append(f"DNS            {pkt.dns.qtype} {pkt.dns.name} ({'response' if pkt.dns.is_response else 'query'})")
    if pkt.http:
        lines.append(f"HTTP           {pkt.http.method or pkt.http.status_code} {pkt.http.path or pkt.http.host or ''}".rstrip())
    if pkt.tls:
        lines.append(f"TLS            {pkt.tls.kind} {pkt.tls.version} SNI={pkt.tls.server_name or '-'}")
    if pkt.malformed_reason:
        lines.append(f"decode issue   {pkt.malformed_reason}")
    if pkt.unsupported_protocol:
        lines.append(f"unsupported    {pkt.unsupported_protocol}")
    if pkt.notes:
        lines.extend(["", "NOTES", *[f"- {note}" for note in pkt.notes]])
    if pkt.payload_preview:
        lines.extend(["", f"HEX PREVIEW\n{pkt.payload_preview}"])
    lines.extend(["", "q / Esc closes this inspector."])
    return "\n".join(lines)


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
        self._visible_packets: list[PacketInfo] = []

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
        self._visible_packets = []
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
            self._visible_packets.append(pkt)
        if not rows:
            empty = f"No packets match filter: {self.filter_text}" if needle else "Waiting for packets..."
            table.add_row("", "", "", "", "", empty)
            return
        for row in rows[:MAX_REFRESH_ROWS]:
            table.add_row(*row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Open a field-level inspector for selected live-packet rows."""
        if event.data_table.id != "packets":
            return
        if 0 <= event.cursor_row < len(self._visible_packets):
            self.push_screen(PacketDetailScreen(self._visible_packets[event.cursor_row]))

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
