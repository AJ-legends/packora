# Packora — Project Requirements Document

**Status:** Draft v2 (2026-11-06) — supersedes Draft v1. Incorporates review: version scoping (TCP reassembly & SYN-flood deferred), persona refinement, packet-classification split (unsupported vs malformed), NFR refinement, restructured layout/acceptance/milestones, and resolved open decisions.
**Purpose:** Portfolio project — an educational, terminal-based network packet analyzer: a "mini-Wireshark for the terminal."
**Namer:** Project name is **Packora** (CLI: `packora`, package: `packora`).
**Target stack:** Python 3.11+, scapy, Textual (UI only — no Rich fallback), pytest, ruff + mypy, GitHub Actions, `pyproject.toml`.

> Scope principle: depth over breadth. The first release must stand on its own as a polished packet viewer; advanced analysis ships as v2.

## 0. Version Scoping

| Version | Scope | Milestones |
|---|---|---|
| **v1.0** (initial release) | Install/launch, PCAP replay, core parsing (Ethernet/IPv4/TCP/UDP + DNS/HTTP metadata), live capture, intuitive TUI, filtering, run summary | M0–M4 |
| **v2.x** (later version) | TCP session tracking + stream reassembly, port-scan detection, SYN-flood heuristics, alerts panel | M5–M6 |
| **Release prep** | Testing, documentation, demo GIF, packaging | M7 (applies to each release) |

Rationale for the split: TCP reassembly and SYN-flood detection are the two highest-complexity, highest-rabbit-hole features; deferring them keeps the initial release shippable and demonstrable.

---

## 1. Goals & Non-Goals

### Goals
1. **v1:** Live capture + parse of Ethernet/IPv4/TCP/UDP with DNS and HTTP metadata extraction — developed independently of TCP stream reconstruction.
2. **v1:** An intuitive, user-friendly terminal dashboard (packet table, protocol statistics, filtering, keyboard navigation).
3. **v1:** Work fully from recorded PCAP files (`--replay`), so the project is demo-able on machines without Npcap/admin rights.
4. **v1:** Testable architecture: pure-logic analysis layer unit-tested with synthetic packets and recorded PCAPs in CI.
5. **v2:** TCP session reassembly — reconstruct readable streams (e.g., view a raw HTTP request as text).
6. **v2:** Heuristic security analysis: port-scan detection (configurable threshold) and SYN-flood detection, surfacing alerts in a dedicated panel.

### Non-Goals
- No real-time DPI engine, IDS rules language, or TLS decryption.
- No multi-gigabyte throughput claims — scale target is a busy home/LAN network (~100–500 pkt/s).
- No GUI; the terminal UI is the interface.
- **No persistent packet storage by default** — captured traffic is held in memory for the current session only; writing captures to disk is a possible future feature, not in v1 or v2 scope.
- Defer PyPI publication until the project is stable.
- Explicitly not for hostile use: documented for education and networks the operator owns.

---

## 2. Success Criteria

- A stranger can clone, `pip install -e ".[dev]"`, run `packora --replay demo.pcap` **without admin rights**, and see a working UI.
- Ethernet/IPv4/TCP/UDP packets parse correctly; unsupported and malformed packets never crash the app.
- Port-scan detection (v2) uses a **configurable threshold, default 10**. The test corpus verifies detection with **two scenarios: a 3-port probe (test lowers the threshold) and a 12-port probe (default threshold)** — both must be flagged.
- ≥80% test coverage on the analysis layer; CI green on push (lint, typecheck, tests) on Windows and Ubuntu.
- README with demo GIF + architecture diagram + ethics section.

---

## 3. Personas

| Persona | Primary objective | Key requirements |
|---|---|---|
| **Network Learner** | Understand network communication and protocol behaviour. | Readable packet summaries, protocol breakdown and TCP streams. |
| **Security Analyst-in-training** | Investigate suspicious network activity. | Traffic filtering, session inspection and security alerts. |
| **Portfolio Evaluator** | Assess engineering competence and project quality. | Clear documentation, architecture, tests and working demonstrations. |

(Both the Learner and Analyst personas depend on v2 features for stream inspection and alerts; the Evaluator persona is served from v1 onward.)

---

## 4. Functional Requirements

Requirements marked **[v2]** ship in the later version; unmarked items are v1.0.

### F1 — Capture [v1]
- **F1.1** Live sniffing on a chosen interface via scapy; `--list-interfaces` prints a clean table (Windows interface names are ugly and error-prone — this exists because of that).
- **F1.2** BPF-style capture filter support (`--filter "tcp port 443"`), passed through to scapy.
- **F1.3** `--replay <file.pcap>` reads a capture file instead of live traffic (featured default for demos/tests).
- **F1.4** `--count N` and Ctrl+C graceful shutdown producing a run summary (packets seen, by proto, elapsed).
- **F1.5** Session-only retention: captured packets live in memory while the app runs; no capture is written to disk without an explicit future feature.

### F2 — Packet Classification & Protocol Parsing [v1]
- **F2.1** Layered decode: Ethernet → IP → TCP/UDP → DNS/HTTP. Every packet gets exactly one of three outcomes:
  - **parsed** — fully understood, produces a `PacketInfo`.
  - **unsupported** — structurally fine, but the ethertype/next header/proto is not one Packora handles; report the unknown protocol identifier (e.g., "unsupported ethertype 0x8100"), render a size + hex preview.
  - **malformed/truncated** — structurally broken (bad checksums are *not* an error, but truncated headers are); report the layer and reason, render what could be decoded plus a hex preview.
  Unsupported ≠ malformed: the former is a scoping statement, the latter a data-quality statement, and both must never terminate capture (see N2).
- **F2.2** One-line per-packet summary designed for scanning (dir, src:sport ⇄ dst:dport, proto, len, flags, notable extras like DNS query name).
- **F2.3** DNS: query/response pairing, record type/key shown.
- **F2.4** HTTP: method, path, status code, Host header — extracted **per-packet from payload bytes only**, with no dependency on TCP reassembly (independent development, see §8).

### F3 — Terminal Sessions & Stream Reassembly **[v2]**
- **F3.1** Group packets by (src ip:port, dst ip:port, protocol) into conversations; track a stable session id / index.
- **F3.2** Reassembler orders segments by sequence number, tolerating gaps (insert `...N bytes missing...` marker); handle retransmissions and simple reordering. Ship the 80% version first and document honest limits.
- **F3.3** Stream view: two directions rendered distinctly with timestamps (client vs server colouring), distinguishing parsed payload from unparseable bytes.

### F4 — Detection & Alerts **[v2]**
- **F4.1** Sliding window counters per source IP: SYN-only flows to unique destination ports (SYN without response). **Configurable threshold, default 10 per 60s**, exposed as a CLI argument (see §10 D-6).
- **F4.2** SYN flood detection: ratio of unanswered SYNs plus volume spike per source; coarse educational heuristic, with documented false-positive limits.
- **F4.3** All detections are tunable via CLI arguments (`--scan-threshold` etc.) — no config files required initially.
- **F4.4** Alerts appear in a dedicated panel with timestamp, detection kind, source IP, evidence summary, and suggested next steps ("inspect sessions with …").

### F5 — Terminal UI (revamped for intuitiveness) [v1 core, F4/F3 panels in v2]
Design intent: **a first-time user understands the screen without reading docs.**
- **F5.1** Target layout (v1):
  ```
  ┌ Header: interface | filter | uptime | help hint ────────────┐
  │ ┌─ Live Packets ───────────────┐  ┌─ Protocol Mix ────────┐ │
  │ │ table of recent packets      │  │ bar/spark chart       │ │
  │ │ (scrollable, filterable)     │  └───────────────────────┘ │
  │ │                              │                            │
  │ └──────────────────────────────┘                            │
  └─ Footer: visible key hints (q=quit, /=filter, ?=help) ──────┘
  ```
  v2 adds an **Alerts** panel (and the sessions/stream views of F3). Panels that don't apply to the current version must not appear as empty boxes.
- **F5.2** Keyboard navigation throughout: Tab/arrow focus, visible focus indicator, every view reachable by keyboard.
- **F5.3** Discoverability: persistent footer key hints, a `?` help overlay listing all shortcuts and views, and non-destructive first-run hint text when a view is empty (e.g., "waiting for packets…").
- **F5.4** In-panel regex/substring filter of packet rows (`/`), with clear feedback when nothing matches.
- **F5.5** Status-clear errors inside the UI (missing Npcap, no permission) instead of stack traces — see N1.
- **F5.6** Packets/sec gauge alongside the protocol mix.
- **F5.7** Plain non-TUI fallback (`--no-tui`) printing parsed packet summaries to stdout — scripting/piping friendliness and the debug escape hatch; this is the form M1 delivers first.

### F6 — Command Line [v1]
- Single entry point `packora` (+ `python -m packora` equivalent).
- `packora --help`, `packora --version`.
- Sensible defaults so bare `packora --replay f.pcap` does the right thing; `--interface`/`--filter` control live mode.
- **[v2]** Detection flags: `--scan-threshold N`, later detectors follow the same pattern.

---

## 5. Non-Functional Requirements

- **N1 — Usability**
  - Clear installation and configuration instructions.
  - Informative errors for missing dependencies and permissions.
  - Keyboard navigation within the TUI.
- **N2 — Robustness**
  - Handle malformed, truncated and unsupported packets gracefully (see F2.1 classification).
  - Prevent individual parsing failures from terminating capture.
  - Handle interrupted capture sessions safely (clean teardown + summary on Ctrl+C, terminal state restored).
- **N3 — Performance**
  - Retain the **200 pkt/s target as a preliminary benchmark**.
  - Measure processing throughput and UI responsiveness separately.
  - Batch UI updates (tick-based, not per-packet) to prevent rendering bottlenecks.
- **N4 — Testability**
  - Keep capture and analysis independently testable.
  - Use synthetic packets and recorded PCAP files.
  - No live network access should be required for automated tests.
- **N5 — Portability**
  - Windows 10/11 and Ubuntu Linux.
  - Graceful degradation when Npcap or libpcap is unavailable — instructions, not crashes.
  - Consistent replay behaviour across supported platforms.
- **N6 — Code Quality:** type hints, ruff clean, mypy clean; the UI layer may remain smoke-tested (≥80% coverage is required only for the analysis layer).
- **N7 — Licensing & Ethics:** MIT or Apache-2.0 license; "authorized networks only" notice in README, `--help` banner, and app header. Sanitise sample captures and avoid exposing unnecessary payload content (credentials redacted by default).

---

## 6. Interface Contracts (internal)

```
packora/
├── __main__.py           # python -m entry
├── cli.py                # argparse/click definition → runs App
├── capture/
│   ├── base.py           # Feed protocol: iterator of (ts, raw_frame)
│   ├── live.py           # LiveCapture (scapy)
│   └── replay.py         # ReplayFeed (PCAP)
├── parsers/
│   ├── ethernet.py
│   ├── ip.py
│   ├── transport.py      # tcp/udp common handling
│   ├── dns.py
│   └── http.py
├── models/
│   ├── packet.py         # PacketInfo + classification (parsed/unsupported/malformed)
│   └── session.py        # [v2] conversation + stream models
├── analysis/
│   ├── controller.py     # orchestrates capture → analysis → display
│   ├── sessions.py       # [v2] grouping + reassembly
│   └── analyzers/        # [v2] pluggable detection heuristics (port_scan.py…)
├── ui/
│   ├── app.py            # Textual app, panel wiring
│   └── widgets/
└── reporting.py          # run summary export [stretch]
```

- **Feed contract:** `capture/base.py` defines the single protocol both `LiveCapture` and `ReplayFeed` satisfy — everything downstream is identical for live vs replay.
- **Neutral models:** parsers never leak scapy types; they emit dataclasses from `models/packet.py` so tests can build them by hand and the analysis/UI layers never import scapy.
- **Classification contract:** every input frame yields exactly one `parsed` / `unsupported` / `malformed` result (F2.1) — never an exception propagating upward (N2).
- v1 delivers `models/session.py` and `analysis/` as stubs or omits them (python modules that exist but carry a documented "v2" placeholder is acceptable).

---

## 7. Acceptance Criteria

Purposefully split so no single unfinished feature blocks verification of others (even a one-liner like "replay runs the TUI, alerts fire, sessions reassemble" is three independent tests).

### A. Core functionality [v1]
- [ ] Application installs and launches successfully (`pip install -e .`; `packora --version`).
- [ ] PCAP replay works without administrative privileges.
- [ ] Ethernet, IPv4, TCP and UDP packets are correctly parsed.
- [ ] Unsupported and malformed packets are handled without crashing — and are distinguishable from each other (F2.1).

### B. Advanced functionality [(v1) / (v2)]
- [ ] **(v1)** DNS and HTTP metadata are correctly extracted (without depending on stream reassembly).
- [ ] **(v2)** TCP sessions are grouped and reconstructed for supported scenarios.
- [ ] **(v2)** Missing TCP segments are identified and marked.
- [ ] **(v2)** Port-scan detection passes synthetic test scenarios: a 3-port probe with the lowered test threshold, and a 12-port probe with the default threshold (10).
- [ ] **(v2)** Alerts display timestamps, source IPs and supporting evidence.

### C. Application usability [v1]
- [ ] Live capture works on supported interfaces.
- [ ] TUI displays packets, protocol statistics and alerts (alerts = v2 panel).
- [ ] Packet filtering works (BPF on capture; in-panel row filter in TUI).
- [ ] Graceful shutdown produces an accurate run summary.
- [ ] All views are keyboard-navigable; help overlay lists shortcuts.

### D. Engineering quality [v1]
- [ ] Automated tests pass (no live network required).
- [ ] Ruff and Mypy checks pass.
- [ ] CI runs successfully on Windows and Ubuntu.
- [ ] README, architecture diagram and demonstration GIF are available.
- [ ] Sample PCAP and generator script are included (sanitised).

---

## 8. Milestones

Two structural changes vs v1 of this document: **(A) a working CLI comes before the TUI** — the first usable version parses a PCAP and prints packet summaries, giving something testable before interface complexity; **(B) protocol inspection (M4) is independent of TCP reassembly (M5)** — DNS/HTTP metadata never waits on stream reconstruction.

| Milestone | Deliverable | Scope |
|---|---|---|
| **M0 — Foundation** | Project setup, dependencies, `packora` CLI entry point and CI | v1 |
| **M1 — Packet Analysis** | PCAP replay, core parsing (incl. unsupported/malformed classification) and CLI summaries (`--no-tui`) | v1 |
| **M2 — Live Capture** | Interface selection (`--list-interfaces`), live capture and BPF filtering | v1 |
| **M3 — Terminal Interface** | Textual dashboard (revamped, intuitive: keyboard nav, help overlay, filter), packet table and statistics | v1 |
| **M4 — Protocol Inspection** | DNS and HTTP metadata extraction (per-packet, stream-independent) | v1 |
| **M5 — Session Analysis** | TCP session tracking and stream reassembly *(explicitly out of the initial release)* | v2 |
| **M6 — Security Detection** | Port-scan detection (configurable threshold), SYN-flood heuristics and alerts panel *(explicitly out of the initial release)* | v2 |
| **M7 — Final Release** | Testing, documentation, demo GIF and packaging (run once before v1.0; re-run for v2) | both |

**v1.0 ships at end of M4 + release checklist from M7.** M5–M6 land as v2.

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Npcap/admin needed on Windows for live mode | Lead with `--replay`; detect & instruct on missing Npcap; tests use synthetic packets |
| Malformed or unusual packets | Defensive parsing and synthetic test cases |
| High traffic volume causing UI lag | Buffered packet processing and batched UI updates |
| Incorrect detection results | Test against known traffic patterns; document heuristic limitations |
| Sensitive information in packet captures | Use sanitised sample captures and avoid unnecessary payload exposure |
| Textual learning curve eats time | M3 kept minimal; help overlay/footer patterns are simple first; CLI from M1 remains a working fallback |
| TCP reassembly rabbit hole (OOO, retransmit edge cases) | Deferred to v2 — ship the 80% version, document gaps honestly |
| Scope creep (Wireshark envy) | Non-goals + version scoping are the contract; stretch ideas live out-of-scope |

---

## 10. Resolved Decisions

| # | Question | Decision |
|---|---|---|
| 1 | Project name | **Packora** (CLI `packora`, package `packora`, repo keeps "Packet_Sniffer" folder or renames once scaffolding starts) |
| 2 | Rich fallback vs Textual-only | **Textual-only** — avoid maintaining two presentation systems |
| 3 | Python version | **3.11+** for compatibility |
| 4 | Publish to PyPI | **Defer** until the project is stable |
| 5 | Traffic storage beyond current session? | **No persistent storage by default** (in-memory for session only) |
| 6 | Detection thresholds configurable? | **Yes — via CLI arguments initially** (no config files yet); revisit if the flag list grows |
