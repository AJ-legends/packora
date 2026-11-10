"""Pluggable detection analyzers (PRD F4, v2)."""

from __future__ import annotations

from packora.analysis.analyzers.arp_spoof import ArpSpoofDetector
from packora.analysis.analyzers.base import Alert, Analyzer
from packora.analysis.analyzers.beaconing import BeaconingDetector
from packora.analysis.analyzers.dns_anomaly import DnsAnomalyDetector
from packora.analysis.analyzers.dns_tunnel import DnsTunnelDetector
from packora.analysis.analyzers.icmp_flood import IcmpFloodDetector
from packora.analysis.analyzers.port_scan import PortScanDetector
from packora.analysis.analyzers.syn_flood import SynFloodDetector


def default_analyzers(
    scan_threshold: int = 10,
    flood_threshold: int = 100,
    dns_threshold: int = 100,
    icmp_threshold: int = 50,
    dns_tunnel_threshold: int = 8,
    beacon_threshold: int = 6,
) -> list[Analyzer]:
    return [
        PortScanDetector(threshold=scan_threshold),
        SynFloodDetector(threshold=flood_threshold),
        DnsAnomalyDetector(threshold=dns_threshold),
        DnsTunnelDetector(threshold=dns_tunnel_threshold),
        IcmpFloodDetector(threshold=icmp_threshold),
        ArpSpoofDetector(),
        BeaconingDetector(threshold=beacon_threshold),
    ]


__all__ = [
    "Alert",
    "Analyzer",
    "ArpSpoofDetector",
    "BeaconingDetector",
    "DnsAnomalyDetector",
    "DnsTunnelDetector",
    "IcmpFloodDetector",
    "PortScanDetector",
    "SynFloodDetector",
    "default_analyzers",
]
