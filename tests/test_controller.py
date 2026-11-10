"""Controller + reporting integration tests over the committed demo PCAP (PRD F1, F6)."""

from __future__ import annotations

from pathlib import Path

import pytest
from packora import reporting
from packora.analysis.analyzers import default_analyzers
from packora.analysis.controller import Controller
from packora.capture.replay import ReplayFeed
from packora.models.packet import Classification

from conftest import demo_pcap_path


@pytest.fixture
def summary_state() -> Controller:
    feed = ReplayFeed(str(demo_pcap_path()))
    controller = Controller(feed, analyzers=default_analyzers(scan_threshold=10))
    controller.run()
    return controller


def test_replay_processes_all_frames(summary_state: Controller) -> None:
    assert summary_state.total == 24  # the exact load crafted by samples/generate_demo.py


def test_controller_max_packets_limits_replay() -> None:
    controller = Controller(ReplayFeed(str(demo_pcap_path())), max_packets=3)
    controller.run()
    assert controller.total == 3


def test_summary_uses_aggregate_counts_not_retained_rows(summary_state: Controller) -> None:
    summary = reporting.run_summary_text(
        mode="replay",
        target=summary_state.description(),
        filter_expr=None,
        packets=list(summary_state.recent),
        alerts=list(summary_state.alerts),
        started_wall=0.0,
        detect_enabled=True,
        total_packets=501,
        protocol_mix=[("TCP", 501)],
    )
    assert "packets    : 501" in summary
    assert "  TCP" in summary and "501" in summary


def test_every_classification_reached(summary_state: Controller) -> None:
    seen = {pkt.classification for pkt in summary_state.recent}
    assert Classification.PARSED in seen
    assert Classification.UNSUPPORTED in seen
    assert Classification.MALFORMED in seen


def test_dns_and_http_metadata_extracted(summary_state: Controller) -> None:
    http_req = [pkt for pkt in summary_state.recent if pkt.http and pkt.http.kind == "request"]
    assert http_req, "HTTP request metadata should be extractable from the demo capture"
    assert http_req[0].http is not None and http_req[0].http.path == "/index.html"
    dns_queries = [pkt for pkt in summary_state.recent if pkt.dns and not pkt.dns.is_response]
    assert dns_queries and dns_queries[0].dns is not None
    assert dns_queries[0].dns.name == "example.test"


def test_port_scan_detected_with_default_threshold(summary_state: Controller) -> None:
    alerts = list(summary_state.alerts)
    assert any(alert.kind == "port_scan" and alert.src == "10.99.0.10" for alert in alerts)
    # The 3-port probe must NOT alert under the default threshold (10).
    assert not any(alert.src == "10.99.0.11" for alert in alerts)


def test_lowercase_threshold_alert_fires_when_lowered() -> None:
    feed = ReplayFeed(str(demo_pcap_path()))
    controller = Controller(feed, analyzers=default_analyzers(scan_threshold=3))
    controller.run()
    assert any(alert.src == "10.99.0.11" for alert in controller.alerts)


def test_sessions_track_conversations(summary_state: Controller) -> None:
    conversations = summary_state.sessions.ordered()
    assert conversations, "sessions should be grouped from the demo traffic"
    http_conv = [
        conv
        for conv in conversations
        if {conv.client[1], conv.server[1]} & {80}
    ]
    assert http_conv, "the HTTP conversation should be tracked"


def test_stats_mix_populated(summary_state: Controller) -> None:
    mix = dict(summary_state.stats.mix())
    assert mix.get("TCP", 0) >= 1
    assert mix.get("DNS", 0) >= 1
    assert mix.get("unsupported", 0) >= 1
    assert mix.get("malformed", 0) >= 1


def test_rate_and_snapshot_reportable(summary_state: Controller) -> None:
    snapshot = summary_state.snapshot()
    assert snapshot.total == summary_state.total
    assert snapshot.stopped is True
    assert snapshot.error is None
    assert snapshot.rate >= 0
    assert len(snapshot.mix) >= 1
    assert summary_state.stats.rate_per_second() >= 0


def test_demo_pcap_exists_and_is_valid(tmp_path: Path) -> None:
    path = demo_pcap_path()
    assert path.exists()
    assert path.stat().st_size > 0
