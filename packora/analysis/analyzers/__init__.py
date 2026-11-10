"""Pluggable detection analyzers (PRD F4, v2)."""

from __future__ import annotations

from packora.analysis.analyzers.base import Alert, Analyzer
from packora.analysis.analyzers.dns_anomaly import DnsAnomalyDetector
from packora.analysis.analyzers.port_scan import PortScanDetector
from packora.analysis.analyzers.syn_flood import SynFloodDetector


def default_analyzers(
    scan_threshold: int = 10,
    flood_threshold: int = 100,
    dns_threshold: int = 100,
) -> list[Analyzer]:
    return [
        PortScanDetector(threshold=scan_threshold),
        SynFloodDetector(threshold=flood_threshold),
        DnsAnomalyDetector(threshold=dns_threshold),
    ]


__all__ = [
    "Alert",
    "Analyzer",
    "DnsAnomalyDetector",
    "PortScanDetector",
    "SynFloodDetector",
    "default_analyzers",
]
