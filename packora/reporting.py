"""Run summaries and reporting (PRD F1.4, section 6)."""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import TYPE_CHECKING

from packora.analysis.analyzers.base import Alert
from packora.models.packet import Classification

if TYPE_CHECKING:
    from collections.abc import Iterable

    from packora.models.packet import PacketInfo

ALERT_MARK = "! ALERT"
_TABLE_WIDTHS = (8, 11, 10, 23, 23, 46)


def print_packet_table_header() -> None:
    """Print a compact, dependency-free table for `--no-tui` replay/live output."""
    _print_table_rule()
    print(_format_table_row(("time", "outcome", "protocol", "source", "destination", "details")))
    _print_table_rule()


def print_packet_table_row(pkt: PacketInfo) -> None:
    """Render a single neutral packet model as an aligned ASCII table row."""
    timestamp = datetime.fromtimestamp(pkt.ts).strftime("%H:%M:%S")
    protocol = pkt.proto_name or "NETWORK"
    source = _endpoint(pkt.src_ip, pkt.src_port, pkt.src_mac)
    destination = _endpoint(pkt.dst_ip, pkt.dst_port, pkt.dst_mac)
    print(
        _format_table_row(
            (
                timestamp,
                pkt.classification.value.upper(),
                protocol,
                source,
                destination,
                _packet_detail(pkt),
            )
        )
    )


def print_packet_table_footer() -> None:
    _print_table_rule()


def _endpoint(ip: str | None, port: int | None, mac: str | None) -> str:
    if ip:
        return f"{ip}:{port}" if port is not None else ip
    return mac or "-"


def _packet_detail(pkt: PacketInfo) -> str:
    if pkt.classification is Classification.MALFORMED:
        return pkt.malformed_reason or "malformed packet"
    if pkt.classification is Classification.UNSUPPORTED:
        return pkt.unsupported_protocol or "unsupported protocol"
    details: list[str] = []
    if pkt.tcp_flags and pkt.tcp_flags.as_str() != "-":
        details.append(f"flags={pkt.tcp_flags.as_str()}")
    if pkt.dns:
        details.append(f"{'response' if pkt.dns.is_response else 'query'} {pkt.dns.qtype} {pkt.dns.name}")
    if pkt.http:
        details.append(f"{pkt.http.method or pkt.http.status_code} {pkt.http.path or pkt.http.host or ''}".strip())
    if pkt.tls:
        details.append(f"{pkt.tls.kind} {pkt.tls.server_name or pkt.tls.version}")
    if pkt.dhcp:
        details.append(f"{pkt.dhcp.message_type} {pkt.dhcp.hostname or ''}".strip())
    if pkt.ntp:
        details.append(f"{pkt.ntp.mode} v{pkt.ntp.version}")
    details.extend(pkt.notes[:1])
    return "; ".join(details) or f"{pkt.payload_len} payload bytes"


def _format_table_row(values: tuple[str, str, str, str, str, str]) -> str:
    cells = [_truncate(value, width) for value, width in zip(values, _TABLE_WIDTHS, strict=True)]
    return "| " + " | ".join(cell.ljust(width) for cell, width in zip(cells, _TABLE_WIDTHS, strict=True)) + " |"


def _print_table_rule() -> None:
    print("+-" + "-+-".join("-" * width for width in _TABLE_WIDTHS) + "-+")


def _truncate(value: str, width: int) -> str:
    return value if len(value) <= width else value[: width - 3] + "..."


def print_alert_line(alert: Alert) -> None:
    timestamp = datetime.fromtimestamp(alert.ts).strftime("%H:%M:%S")
    print(
        f"{ALERT_MARK} [{timestamp}] [{alert.confidence.upper()}] "
        f"{alert.kind} src={alert.src} {alert.evidence}"
    )


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
            lines.append(
                f"  [{stamp}] [{one_alert.confidence.upper()}] {one_alert.kind} "
                f"src={one_alert.src} {one_alert.evidence}"
            )
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
        "tls": None if pkt.tls is None else {
            "kind": pkt.tls.kind,
            "version": pkt.tls.version,
            "server_name": pkt.tls.server_name,
        },
        "dhcp": None if pkt.dhcp is None else {
            "message_type": pkt.dhcp.message_type,
            "hostname": pkt.dhcp.hostname,
            "requested_ip": pkt.dhcp.requested_ip,
        },
        "ntp": None if pkt.ntp is None else {
            "version": pkt.ntp.version,
            "mode": pkt.ntp.mode,
            "stratum": pkt.ntp.stratum,
        },
        "arp": None if pkt.arp_sender_ip is None else {
            "sender_ip": pkt.arp_sender_ip,
            "sender_mac": pkt.arp_sender_mac,
            "target_ip": pkt.arp_target_ip,
        },
    }


def json_alert(alert: Alert) -> dict:
    return {
        "ts": alert.ts,
        "kind": alert.kind,
        "src": alert.src,
        "evidence": alert.evidence,
        "recommendation": alert.recommendation,
        "confidence": alert.confidence,
        "related_signals": list(alert.related_signals),
    }
