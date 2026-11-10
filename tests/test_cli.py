"""CLI behavior tests (PRD F6) + reporting export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from packora import cli

from conftest import demo_pcap_path


def test_version(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "packora 1.0.0" in out


def test_no_args_prints_usage_hint(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main([])
    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert "--replay" in err


def test_help_shows_ethics_notice(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "authorized networks only" in out.lower()
    assert "--scan-threshold" in out


def test_list_interfaces_never_crashes(capsys: pytest.CaptureFixture) -> None:
    cli.main(["--list-interfaces"])
    out = capsys.readouterr().out
    assert "interface" in out.lower() or "no capture interfaces" in out.lower()


def test_replay_no_tui_outputs_summaries_and_alerts(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--replay", str(demo_pcap_path()), "--no-tui"])
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "Packora run summary" in out
    assert "port_scan" in out
    assert "DNS" in out
    assert "MALFORMED: truncated or short IPv4 header" in out
    assert "UNSUPPORTED" in out


def test_replay_export_summary_json(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    target = tmp_path / "summary.json"
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--replay", str(demo_pcap_path()), "--no-tui", "--export-summary", str(target)])
    assert exit_info.value.code == 0
    content = json.loads(target.read_text(encoding="utf-8"))
    assert content["mode"] == "replay"
    assert content["detection_enabled"] is True
    alert_kinds = {a["kind"] for a in content["alerts"]}
    assert "port_scan" in alert_kinds
    http_packets = [p for p in content["packets"] if p.get("http")]
    assert http_packets and http_packets[0]["http"]["path"] == "/index.html"
