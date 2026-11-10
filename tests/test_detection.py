"""Detection analyzer tests (PRD F4): port scan, SYN flood, DNS anomaly, cooldowns."""

from __future__ import annotations

from packora.analysis.analyzers.arp_spoof import ArpSpoofDetector
from packora.analysis.analyzers.beaconing import BeaconingDetector
from packora.analysis.analyzers.dns_anomaly import DnsAnomalyDetector
from packora.analysis.analyzers.dns_tunnel import DnsTunnelDetector
from packora.analysis.analyzers.icmp_flood import IcmpFloodDetector
from packora.analysis.analyzers.port_scan import PortScanDetector
from packora.analysis.analyzers.syn_flood import SynFloodDetector
from packora.models.packet import Classification, DnsInfo, PacketInfo, TcpFlags

SCANNER = "10.0.0.9"
TARGET = "10.0.1.1"


def syn_to(port: int, ts: float, src: str = SCANNER) -> PacketInfo:
    return PacketInfo(
        ts=ts,
        wire_len=54,
        classification=Classification.PARSED,
        src_ip=src,
        dst_ip=TARGET,
        ip_proto=6,
        proto_name="TCP",
        src_port=40000,
        dst_port=port,
        tcp_flags=TcpFlags(syn=True),
        seq=1,
    )


def synack_for(probe: PacketInfo, ts: float) -> PacketInfo:
    return PacketInfo(
        ts=ts,
        wire_len=54,
        classification=Classification.PARSED,
        src_ip=probe.dst_ip,
        dst_ip=probe.src_ip,
        ip_proto=6,
        proto_name="TCP",
        src_port=probe.dst_port,
        dst_port=probe.src_port,
        tcp_flags=TcpFlags(syn=True, ack=True),
        seq=1,
    )


def test_default_threshold_trips_at_ports() -> None:
    detector = PortScanDetector(threshold=10)
    alerts = []
    for idx, port in enumerate(range(21, 21 + 12), start=1):
        result = detector.observe(syn_to(port, ts=1.0 + idx * 0.01))
        alerts.extend(result)
    alerts.extend(detector.finalize(2.0))
    # Distinct ports 21..32: alert must fire once threshold (10) is reached.
    assert len(alerts) == 1
    assert alerts[0].kind == "port_scan"
    assert SCANNER in alerts[0].src
    assert "12 unanswered SYN probes" in alerts[0].evidence


def test_three_port_probe_with_lowered_threshold() -> None:
    detector = PortScanDetector(threshold=3)
    alerts = []
    for idx, port in enumerate((8000, 8001, 8002), start=1):
        alerts.extend(detector.observe(syn_to(port, ts=1.0 + idx * 0.01)))
    alerts.extend(detector.finalize(2.0))
    assert len(alerts) == 1
    assert "3 unanswered SYN probes" in alerts[0].evidence


def test_below_threshold_no_alert() -> None:
    detector = PortScanDetector(threshold=10)
    alerts = []
    for idx, port in enumerate(range(22, 30), start=1):  # 8 distinct ports
        alerts.extend(detector.observe(syn_to(port, ts=1.0 + idx * 0.01)))
    assert not alerts


def test_cooldown_suppresses_realert() -> None:
    detector = PortScanDetector(threshold=5, cooldown_seconds=60.0)
    for port in range(1, 6):
        detector.observe(syn_to(port, ts=1.0 + port * 0.01))
    first = detector.finalize(2.0)
    for port in range(6, 11):
        detector.observe(syn_to(port, ts=2.1 + port * 0.01))
    second = detector.finalize(3.5)
    assert len(first) == 1
    assert not second  # cooldown window suppresses the second alert


def test_answered_syns_do_not_create_port_scan_alert() -> None:
    detector = PortScanDetector(threshold=3)
    for idx, port in enumerate((80, 443, 8080), start=1):
        probe = syn_to(port, ts=float(idx))
        detector.observe(probe)
        detector.observe(synack_for(probe, ts=float(idx) + 0.1))
    assert detector.finalize(5.0) == []


def test_window_slides_old_probes_out() -> None:
    detector = PortScanDetector(threshold=5, window_seconds=10.0)
    alerts = []
    for idx, port in enumerate((21, 22, 23, 24), start=1):
        alerts.extend(detector.observe(syn_to(port, ts=idx * 1.0)))
    assert not alerts
    # ports aged out; only one recent probe
    alerts.extend(detector.observe(syn_to(25, ts=30.0)))
    assert not alerts


def test_syn_flood_volume_threshold() -> None:
    detector = SynFloodDetector(threshold=100, window_seconds=10.0)
    alerts = []
    for idx in range(100):
        alerts.extend(detector.observe(syn_to(80, ts=1.0 + idx * 0.05)))
    alerts.extend(detector.finalize(7.0))
    assert len(alerts) == 1
    assert alerts[0].kind == "syn_flood"
    assert "100/100 unanswered SYNs" in alerts[0].evidence


def test_syn_flood_cooldown() -> None:
    detector = SynFloodDetector(threshold=10, cooldown_seconds=60.0)
    first: list = []
    for idx in range(20):
        first.extend(detector.observe(syn_to(80, ts=1.0 + idx * 0.2)))
    assert len(first) == 1
    # A fresh storm well outside the cooldown window must re-alert.
    late: list = []
    base_ts = 1.0 + 20 * 0.2 + 80.0
    for idx in range(10):
        late.extend(detector.observe(syn_to(81, ts=base_ts + idx * 0.2)))
    late.extend(detector.finalize(base_ts + 3.0))
    assert len(late) == 1
    assert late[0].ts > first[0].ts + 60.0


def test_answered_syns_do_not_create_flood_alert() -> None:
    detector = SynFloodDetector(threshold=3, response_grace_seconds=0.1)
    for idx in range(3):
        probe = syn_to(80, ts=1.0 + idx * 0.1)
        detector.observe(probe)
        detector.observe(synack_for(probe, ts=1.05 + idx * 0.1))
    assert detector.finalize(2.0) == []


def test_dns_anomaly_alert() -> None:
    detector = DnsAnomalyDetector(threshold=50, window_seconds=60.0)
    alerts = []
    for idx in range(50):
        name = f"host{idx}.example.test"
        pkt = PacketInfo(
            ts=1.0 + idx * 0.02,
            wire_len=80,
            classification=Classification.PARSED,
            src_ip=SCANNER,
            ip_proto=17,
            proto_name="DNS",
            src_port=53000,
            dst_port=53,
            dns=DnsInfo(name=name, qtype="A", is_response=False, answer_count=0),
        )
        alerts.extend(detector.observe(pkt))
    assert len(alerts) == 1
    assert alerts[0].kind == "dns_anomaly"


def test_dns_tunnel_heuristic_requires_long_distinct_labels() -> None:
    detector = DnsTunnelDetector(threshold=3, min_label_length=10)
    alerts = []
    for index in range(3):
        pkt = PacketInfo(
            ts=float(index),
            wire_len=90,
            classification=Classification.PARSED,
            src_ip=SCANNER,
            ip_proto=17,
            proto_name="DNS",
            dns=DnsInfo(name=f"{index:010d}payload.example.test", qtype="A", is_response=False, answer_count=0),
        )
        alerts.extend(detector.observe(pkt))
    assert len(alerts) == 1
    assert alerts[0].kind == "dns_tunnel_suspected"


def test_arp_conflicting_mapping_alerts_once() -> None:
    detector = ArpSpoofDetector()
    first = PacketInfo(ts=1.0, wire_len=42, classification=Classification.PARSED, arp_sender_ip="10.0.0.1", arp_sender_mac="00:11:22:33:44:55")
    changed = PacketInfo(ts=2.0, wire_len=42, classification=Classification.PARSED, arp_sender_ip="10.0.0.1", arp_sender_mac="66:77:88:99:aa:bb")
    assert detector.observe(first) == []
    alerts = detector.observe(changed)
    assert len(alerts) == 1
    assert alerts[0].kind == "arp_mapping_conflict"


def test_icmp_burst_alerts() -> None:
    detector = IcmpFloodDetector(threshold=3)
    alerts = []
    for index in range(3):
        alerts.extend(
            detector.observe(
                PacketInfo(
                    ts=float(index), wire_len=42, classification=Classification.PARSED,
                    src_ip=SCANNER, proto_name="ICMP", notes=["ICMP echo_request (type=8, code=0)"],
                )
            )
        )
    assert len(alerts) == 1
    assert alerts[0].kind == "icmp_flood"


def test_periodic_payloads_alert_but_irregular_traffic_does_not() -> None:
    regular = BeaconingDetector(threshold=4)
    alerts = []
    for timestamp in (0.0, 10.0, 20.0, 30.0):
        alerts.extend(regular.observe(PacketInfo(ts=timestamp, wire_len=80, classification=Classification.PARSED, src_ip=SCANNER, dst_ip=TARGET, src_port=50000, dst_port=443, ip_proto=6, payload_len=10)))
    assert len(alerts) == 1
    assert alerts[0].kind == "periodic_beaconing"
    irregular = BeaconingDetector(threshold=4)
    for timestamp in (0.0, 1.0, 25.0, 80.0):
        assert irregular.observe(PacketInfo(ts=timestamp, wire_len=80, classification=Classification.PARSED, src_ip=SCANNER, dst_ip=TARGET, src_port=50000, dst_port=443, ip_proto=6, payload_len=10)) == []
