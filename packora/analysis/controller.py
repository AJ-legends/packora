"""Analysis controller: the only place capture, parsing, and analysis are wired (PRD section 6).

UI never joins this thread's work; callers drain shared state at their own pace
(N3: batched reads), which keeps rendering decoupled from capture throughput.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.analysis.sessions import SessionTracker
from packora.analysis.stats import StatsTracker
from packora.capture.base import Feed, Frame
from packora.models.packet import PacketInfo
from packora.models.session import Conversation
from packora.parsers import parse_frame

BATCH_SIZE = 32
EVIDENCE_WINDOW_SECONDS = 300.0


@dataclass(frozen=True)
class Snapshot:
    """Thread-consistent read view handed to one UI tick (N3)."""

    total: int
    stopped: bool
    error: str | None
    rate: float
    mix: list[tuple[str, int]]
    recent: list[PacketInfo]
    alerts: list[Alert]
    conversations: list[Conversation]
    description: str


class Controller:
    """Drives capture -> parse -> analyze, exposing thread-safe read views."""

    def __init__(
        self,
        feed: Feed,
        analyzers: list[Analyzer] | None = None,
        max_rows: int = 500,
        max_alerts: int = 200,
        max_packets: int | None = None,
    ) -> None:
        self.feed = feed
        self.stats = StatsTracker()
        self.sessions = SessionTracker()
        self.analyzers: list[Analyzer] = analyzers or []
        self.recent: deque[PacketInfo] = deque(maxlen=max_rows)
        self.alerts: deque[Alert] = deque(maxlen=max_alerts)
        self.started_ts: float | None = None
        self.stopped = False
        self.error: str | None = None
        self.total = 0
        self.max_packets = max_packets
        self._analyzers_finalized = False
        self._lock = threading.RLock()
        self._alert_signals: defaultdict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def description(self) -> str:
        return self.feed.description

    def observe(self, pkt: PacketInfo) -> bool:
        """Run all per-packet handlers; return True when this packet created an alert."""
        with self._lock:
            self.stats.observe(pkt)
            self.recent.append(pkt)
            self.total += 1
            self.sessions.observe(pkt)
            created = False
            for analyzer in self.analyzers:
                for alert in analyzer.observe(pkt):
                    self.alerts.append(self._score_alert(alert))
                    created = True
            return created

    def process(self, frame: Frame) -> PacketInfo:
        """Parse one frame under the classification contract, then observe it."""
        pkt = parse_frame(frame)
        self.observe(pkt)
        return pkt

    def finalize_analyzers(self, ts: float | None) -> None:
        """Flush time-delayed detector evidence once, including at replay end."""
        with self._lock:
            if self._analyzers_finalized or ts is None:
                return
            self._analyzers_finalized = True
            for analyzer in self.analyzers:
                for alert in analyzer.finalize(ts):
                    self.alerts.append(self._score_alert(alert))

    def _score_alert(self, alert: Alert) -> Alert:
        """Attach transparent confidence based on independent detector corroboration."""
        signals = self._alert_signals[alert.src]
        horizon = alert.ts - EVIDENCE_WINDOW_SECONDS
        while signals and signals[0][0] < horizon:
            signals.popleft()
        signals.append((alert.ts, alert.kind))
        related = tuple(sorted({kind for _, kind in signals}))
        confidence = "high" if len(related) >= 2 else alert.confidence
        if len(related) >= 3:
            confidence = "critical"
        return replace(alert, confidence=confidence, related_signals=related)

    def run(self, should_continue: Callable[[], bool] | None = None, replay_speed: float = 0.0) -> None:
        """Blocking consumption of `self.feed` — set up once, run inline or in a thread.

        Never lets an exception escape silently (N1): capture failures are stored
        in `self.error` for the CLI/UI to surface.
        """
        self.stopped = False
        self._stop.clear()
        self._analyzers_finalized = False
        previous_ts: float | None = None
        last_ts: float | None = None
        try:
            for frame in self.feed.frames():
                if self._stop.is_set():
                    break
                if should_continue is not None and not should_continue():
                    break
                if self.max_packets is not None and self.total >= self.max_packets:
                    break
                self.process(frame)
                last_ts = frame.ts
                if self.started_ts is None:
                    self.started_ts = frame.ts
                if replay_speed > 0 and previous_ts is not None:
                    delay = (frame.ts - previous_ts) / replay_speed
                    if delay > 0:
                        threading.Event().wait(delay)
                previous_ts = frame.ts
        except Exception as exc:  # noqa: BLE001 - capture failures must be reported, not vanish
            self.error = f"{exc}"
        finally:
            # A feed that failed internally (e.g. live capture without Npcap) ends its
            # iteration cleanly — surface its stored error instead (PRD N1).
            feed_error = getattr(self.feed, "error", None)
            if self.error is None and feed_error:
                self.error = feed_error
            self.finalize_analyzers(last_ts)
            self.stopped = True

    def start_thread(self, **run_kwargs: object) -> None:
        self._thread = threading.Thread(target=self.run, kwargs=run_kwargs, daemon=True)
        self._thread.start()

    def stop_thread(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def drain_recent(self, limit: int = 50) -> list[PacketInfo]:
        """Tail slice for UI consumers (thread-safe read via deque bound)."""
        with self._lock:
            if len(self.recent) <= limit:
                return list(self.recent)
            return list(self.recent)[-limit:]

    def snapshot(self) -> Snapshot:
        """Thread-consistent read view for one UI tick (N3)."""
        with self._lock:
            return Snapshot(
                total=self.total,
                stopped=self.stopped,
                error=self.error,
                rate=self.stats.rate_per_second(),
                mix=self.stats.mix(),
                recent=self.drain_recent(limit=200),
                alerts=list(self.alerts)[-20:],
                conversations=self.sessions.ordered(),
                description=self.description(),
            )


def iter_from_feed(feed: Feed) -> Iterator[PacketInfo]:
    """Parses a feed lazily; used by CLI paths that don't need a controller."""
    for frame in feed.frames():
        yield parse_frame(frame)
