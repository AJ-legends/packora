"""Run summaries and reporting (PRD F1.4, section 6)."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import TYPE_CHECKING

from packora.analysis.analyzers.base import Alert

if TYPE_CHECKING:
    from collections.abc import Iterable

    from packora.models.packet import PacketInfo

ALERT_MARK = "! ALERT"


def print_alert_line(alert: Alert) -> None:
    timestamp = datetime.fromtimestamp(alert.ts).strftime("%H:%M:%S")
    print(f"{ALERT_MARK} [{timestamp}] {alert.kind} src={alert.src} {alert.evidence}")


def run_summary_text(
    mode: str,
    target: str,
    filter_expr: str | None,
    packets: Iterable[PacketInfo],
    alerts: Iterable[Alert],
    started_wall: float,
    detect_enabled: bool,
    total_packets: int | None = None,
    protocol_mix: Iterable[tuple[str, int]] | None = None,
) -> str:
    """Human-readable end-of-run summary to stdout (PRD F1.4)."""
    packets = list(packets)
    alerts = list(alerts)
    packet_count = len(packets) if total_packets is None else total_packets
    mix = list(protocol_mix) if protocol_mix is not None else _classification_mix(packets)
    elapsed = time.time() - started_wall
    lines = [
        "",
        "=" * 62,
        "Packora run summary",
        "=" * 62,
        f"mode       : {mode}",
        f"target     : {target}",
        f"bpf-filter : {filter_expr or '(none)'}",
        f"detection  : {'enabled' if detect_enabled else 'disabled'}",
        f"packets    : {packet_count}",
        f"duration   : {elapsed:.2f}s",
        "",
        "Protocol mix",
        "------------",
    ]
    for label, count in mix:
        lines.append(f"  {label:<12} {count}")
    if alerts:
        lines += ["", f"Alerts ({len(alerts)})", "--------"]
        for one_alert in alerts:
            stamp = datetime.fromtimestamp(one_alert.ts).strftime("%H:%M:%S")
            lines.append(f"  [{stamp}] {one_alert.kind} src={one_alert.src} {one_alert.evidence}")
    else:
        lines.append("Alerts     : none raised")
    return "\n".join(lines)


def run_summary_json(
    mode: str,
    target: str,
    filter_expr: str | None,
    packets: Iterable[PacketInfo],
    alerts: Iterable[Alert],
    started_wall: float,
    detect_enabled: bool,
    total_packets: int | None = None,
    protocol_mix: Iterable[tuple[str, int]] | None = None,
) -> str:
    """Machine-readable summary (reporting.py contract)."""
    packets = list(packets)
    mix = list(protocol_mix) if protocol_mix is not None else _classification_mix(packets)
    return json.dumps(
        {
            "mode": mode,
            "target": target,
            "filter": filter_expr,
            "detection_enabled": detect_enabled,
            "duration_s": round(time.time() - started_wall, 3),
            "packet_count": len(packets) if total_packets is None else total_packets,
            "protocol_mix": dict(mix),
            "packets": [json_packet(p) for p in packets],
            "alerts": [json_alert(a) for a in alerts],
        },
        indent=2,
    )


def _classification_mix(packets: Iterable[PacketInfo]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for pkt in packets:
        counts[pkt.classification.value] = counts.get(pkt.classification.value, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def json_packet(pkt: PacketInfo) -> dict:
    return {
        "ts": pkt.ts,
        "classification": pkt.classification.value,
        "length": pkt.wire_len,
        "src_ip": pkt.src_ip,
        "dst_ip": pkt.dst_ip,
        "ip_proto": pkt.ip_proto,
        "src_port": pkt.src_port,
        "dst_port": pkt.dst_port,
        "summary": pkt.one_liner(),
        "dns": None if pkt.dns is None else {
            "name": pkt.dns.name,
            "qtype": pkt.dns.qtype,
            "is_response": pkt.dns.is_response,
        },
        "http": None if pkt.http is None else {
            "kind": pkt.http.kind,
            "method": pkt.http.method,
            "path": pkt.http.path,
            "status_code": pkt.http.status_code,
            "host": pkt.http.host,
        },
    }


def json_alert(alert: Alert) -> dict:
    return {
        "ts": alert.ts,
        "kind": alert.kind,
        "src": alert.src,
        "evidence": alert.evidence,
        "recommendation": alert.recommendation,
    }
