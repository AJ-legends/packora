# Packora

**Educational terminal packet analyzer — a "mini-Wireshark for the terminal."**

Packora captures or replays network traffic, classifies every packet
(`parsed` / `unsupported` / `malformed`), extracts safe metadata from common
network and application protocols, reassembles TCP streams, and surfaces
explainable security detections in a keyboard-driven Textual dashboard.

> **Authorized networks only.** Capturing traffic on networks you do not own or
> operate may be illegal. Packora exists to teach, not to spy.

## Features

- **PCAP replay first** — `packora --replay` works on any machine with zero special
  privileges; live capture is a first-class mode but needs Npcap (Windows) or libpcap (Linux) plus elevated rights.
- **Packet classification** — every frame resolves to exactly one of
  parsed / unsupported (protocol identifier reported) / malformed (layer + reason reported); a bad capture never stalls the run.
- **Protocol metadata** — Ethernet (including VLAN), ARP, IPv4/IPv6, TCP/UDP,
  ICMP/ICMPv6, DNS, HTTP, TLS ClientHello/ServerHello, DHCPv4, and NTP.
  Truncated headers and malformed variable-length options are contained and
  labelled rather than crashing a run.
- **TCP session reassembly** — conversations grouped bidirectionally, out-of-order
  segments sorted, retransmissions deduped, gaps shown as `...N bytes missing...`.
- **Detections** — explainable, cooldown-protected heuristics for unanswered
  port scans and SYN floods, high-volume DNS, suspected DNS tunnelling, ARP
  mapping conflicts, ICMP bursts, and highly periodic outbound flows. These are
  investigation leads, not verdicts.
- **Terminal dashboard** — live packet table with in-panel filtering, protocol mix
  bars, packets/sec rate, keyboard navigation, `?` help overlay, plain `--no-tui` mode.

## Install

```bash
git clone <this-repo>
cd Packet_Sniffer
python -m venv .venv
.venv\Scripts\activate        # Windows   (Linux: source .venv/bin/activate)
pip install -e ".[dev]"
packora --version
```

## Quick start

```bash
# 1. Explore the committed, fully synthetic sample capture (no privileges needed)
packora --replay samples/demo.pcap
packora --replay samples/demo.pcap --scan-threshold 3     # also see the 3-port probe alert
packora --replay samples/demo.pcap --dns-threshold 50     # tune DNS-anomaly sensitivity

# 2. Plain stdout mode (pipe-friendly)
packora --replay samples/demo.pcap --no-tui
packora --replay samples/demo.pcap --no-tui --export-summary run.json

# 3. Live capture (needs Npcap/root + Administrator)
packora --list-interfaces
packora --interface "<name>" --filter "tcp port 443" --count 500
```

## Dashboard keys

| Key | Action |
|-----|--------|
| `q` | quit (run summary follows) |
| `/` | focus filter box (Enter applies, Esc clears) |
| `?` | help overlay |
| `p` | sessions view → Enter opens the reassembled stream |

## Replay output

`--no-tui` renders an aligned six-column table (time, outcome, protocol,
source, destination, details), followed by the protocol mix and alerts. This
makes it practical to scan output directly or redirect it to a text file.

For larger or real-world training captures, see
[samples/EXTERNAL_CAPTURES.md](samples/EXTERNAL_CAPTURES.md). Downloaded PCAPs
and exported reports are ignored by Git to avoid accidentally publishing
traffic metadata.

## Architecture

```
packora/
├── capture/       scapy lives ONLY here (base Feed contract, live + replay)
├── parsers/       Ethernet/IP/TCP/UDP/DNS/HTTP -> neutral models; classification
├── models/        PacketInfo & friends (no scapy; tests build them by hand)
├── analysis/      controller + sessions/reassembly + analyzers (detections)
├── ui/            Textual dashboard (presentation only)
└── reporting.py   run summaries (text + JSON export)
```

See [PRD.md](PRD.md) for the full requirements document — goals/non-goals,
version scoping (what ships in v1 vs v2), acceptance criteria, and milestones.

## Development

```bash
pytest --cov=packora           # tests; no live network ever needed (synthetic + PCAP)
ruff check .                   # lint
mypy packora                   # typecheck
python -m samples.generate_demo   # regenerate samples/demo.pcap (== committed file)
```

## Roadmap

- **v1.0 (done here)**: replay + parsing + classification + live capture + dashboard + DNS/HTTP metadata.
- **v2 (shipped here as the planned next step)**: TCP session reassembly + port-scan/SYN-flood/DNS detection + alerts panel.
- Later ideas: PCAP write support, geolocation, plugin system, DPI-ish analyzers.

## Notes for Windows users

Raw packet capture requires [Npcap](https://npcap.com/) installed and an
Administrator terminal. Packora always tells you when a capture fails for
that reason — and promotes `--replay`, which needs neither.
