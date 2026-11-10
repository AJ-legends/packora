"""Generate samples/demo.pcap — a sanitised, fully synthetic demo capture.

Everything here is crafted traffic between test/lab addresses; nothing comes
from a real network (PRD section 7 D "sanitised sample captures").

It deliberately includes:
- benign DNS queries/responses and an HTTP request/response round trip,
- HTTPS-style (byte-garbage TCP) traffic that still classifies,
- a 12-port SYN scan (default threshold 10 -> alerts),
- a 3-port probe (use --scan-threshold 3 to see it alert),
- one malformed frame (truncated IPv4) and one unsupported ethertype frame,
so every Packora classification path is visible in a single demo file.

Usage:  python samples/generate_demo.py [out.pcap]
"""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw


def main(out_path: Path) -> None:
    """Actually build the packets (kept verbose and scapy-forward, not clever)."""
    main_mac = "02:00:00:00:00:aa"
    client_mac = "02:00:00:00:00:bb"
    client_ip = "10.0.0.99"
    dns_ip = "10.0.1.53"
    web_ip = "93.184.216.34"

    def stamp(packet: Ether, ts: float) -> Ether:
        packet.time = ts
        return packet

    def from_client(payload: bytes, dst_mac: str) -> Ether:
        return Ether(src=client_mac, dst=dst_mac, type=0x0800) / payload

    def from_main(payload: bytes, to_client: str, src_ip: str, dst_ip: str) -> Ether:
        return (
            Ether(src=main_mac, dst=client_mac, type=0x0800)
            / IP(src=src_ip, dst=dst_ip)
            / payload
        )

    packets: list[Ether] = []
    sports = iter(range(50000, 50400))
    ts = 1700000000.0

    # --- benign DNS round trip ------------------------------------------------
    sport = next(sports)
    query = UDP(sport=sport, dport=53) / DNS(rd=1, qdcount=1, qd=DNSQR(qname="example.test", qtype="A"))
    response = UDP(sport=53, dport=sport) / DNS(qr=1, qd=DNSQR(qname="example.test", qtype="A"), ancount=1)
    packets.append(stamp(from_client(IP(src=client_ip, dst=dns_ip) / query, main_mac), ts))
    ts += 0.15
    packets.append(stamp(from_main(response, client_ip, dns_ip, client_ip), ts))
    ts += 0.4

    # --- HTTP round trip ------------------------------------------------------
    sport = next(sports)
    get_payload = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: packora-demo\r\n\r\n"
    packets.append(
        stamp(
            from_client(
                IP(src=client_ip, dst=web_ip) / TCP(sport=sport, dport=80, seq=1000, flags="PA", window=64240) / Raw(load=get_payload),
                main_mac,
            ),
            ts,
        )
    )
    ts += 0.3
    syn_ack = TCP(sport=80, dport=sport, seq=2000, ack=1050, flags="SA", window=8192)
    packets.append(stamp(from_main(syn_ack, "client", web_ip, client_ip), ts))
    ts += 0.3
    http_payload = b"HTTP/1.0 200 OK\r\nServer: TestSrv\r\nContent-Length: 6\r\n\r\nHello!"
    resp = TCP(sport=80, dport=sport, seq=2001, ack=1050, flags="PA", window=8192) / Raw(load=http_payload)
    packets.append(stamp(from_main(resp, "client", web_ip, client_ip), ts))
    ts += 0.5

    # --- HTTPS-style garbage bytes (classified, no decode) ---------------------
    for seq in (3000, 3020):
        sport = next(sports)
        https = TCP(sport=sport, dport=443, seq=seq, flags="PA", window=64240) / Raw(load=b"\x16\x03\x01\x00\x05abc")
        packets.append(stamp(from_client(IP(src=client_ip, dst=web_ip) / https, main_mac), ts))
        ts += 0.1

    # --- port scan: 12 ports from one host (default threshold 10) --------------
    scan_ip = "10.99.0.10"
    scan_mac = "02:00:00:00:0a:0a"
    for port in (21, 22, 23, 25, 79, 110, 135, 139, 443, 445, 3306, 3389):
        probe = (
            Ether(src=scan_mac, dst=main_mac, type=0x0800)
            / IP(src=scan_ip, dst="10.0.1.20")
            / TCP(sport=60000 + port, dport=port, seq=1, flags="S", window=1024)
        )
        packets.append(stamp(probe, ts))
        ts += 0.01

    # --- 3-port probe (only alerts with --scan-threshold 3) --------------------
    slow_ip = "10.99.0.11"
    for probe_offset, port in enumerate((8000, 8001, 8002)):
        probe = (
            Ether(src="02:00:00:00:0b:0b", dst=main_mac, type=0x0800)
            / IP(src=slow_ip, dst="10.0.1.30")
            / TCP(sport=61000 + probe_offset, dport=port, seq=1, flags="S", window=1024)
        )
        packets.append(stamp(probe, ts))
        ts += 0.01

    ts += 0.5

    # --- malformed frame: truncated IPv4 ---------------------------------------
    bad = Ether(src=client_mac, dst=main_mac, type=0x0800) / Raw(load=b"\x45\x00\x00")
    packets.append(stamp(bad, ts))

    ts += 0.2

    # --- unsupported ethertype ---------------------------------------------------
    vendor = Ether(src=client_mac, dst=main_mac, type=0x88B7) / Raw(load=b"vendor protocol here")
    packets.append(stamp(vendor, ts))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    from scapy.all import wrpcap

    wrpcap(str(out_path), packets)
    print(f"wrote {len(packets)} packets to {out_path}")


if __name__ == "__main__":
    default_out = Path(__file__).resolve().parent / "demo.pcap"
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else default_out)
