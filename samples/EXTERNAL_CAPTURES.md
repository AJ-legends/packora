# External analysis captures

These PCAPs are deliberately excluded from Git. They are third-party training
artifacts and may contain sensitive, malware-related, or otherwise unsuitable
network metadata. Use them only for offline analysis in an isolated, authorized
environment. A PCAP is data, not an executable; do not extract or run transferred
files from it.

## Installed locally

`samples/external/McDB_150724-18-22_FpF90.pcap` is a 1.8 MB public traffic
sample published by Netresec. Its description states that it mixes normal web
traffic with njRAT and Kovter traffic. It is useful for exercising DNS, TLS,
TCP sessions, periodic-flow analysis, and alert presentation.

Source: <https://media.netresec.com/pcap/McDB_150724-18-22_FpF90.pcap>

`samples/external/id1-cn_packet-injection.pcap` is a 74 KB public packet-
injection capture from Netresec's PCAP collection. It uses raw-IP framing, so
it doubles as a compatibility fixture for Packora's non-Ethernet PCAP support.

Source: <https://media.netresec.com/pcap/id1-cn_packet-injection.pcap>

## Recommended additional exercises

- Malware-Traffic-Analysis.net's [2025 fake-software incident exercise](https://www.malware-traffic-analysis.net/2025/01/22/index.html): documented infection-analysis questions and a password-protected PCAP archive.
- The [Ultimate PCAP](https://weberblog.net/the-ultimate-pcap/) for broad protocol-decoder regression checks.

Do not commit downloaded captures or generated `*-summary.json` / `*-detection.json`
reports. They may expose endpoints, hostnames, or other data from the traffic.
