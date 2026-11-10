# AGENTS.md

Status: **implemented (v1 scope + v2 detection features)**. The placeholder era is over; commands below were run and verified against `.venv` (Python 3.13).

## What this is

- **Packora** — educational terminal packet analyzer ("mini-Wireshark for the terminal"). Python 3.11+, scapy, Textual. UI is Textual-only by decision; do not add a Rich fallback.
- `PRD.md` is the requirements contract (version scoping, acceptance criteria, milestone M0–M7). **Read it before adding features**; keep scope tags (`[v2]`) meaningful.

## Environment & commands (verified)

```powershell
python -m venv .venv                                   # one-time
.venv\Scripts\python.exe -m pip install -e ".[dev]"    # everything needed
.venv\Scripts\python.exe -m pytest tests -q            # full suite, no network needed
.venv\Scripts\python.exe -m pytest --cov=packora tests # coverage gate = 80%, enforced via pyproject
.venv\Scripts\python.exe -m ruff check .               # lint (E,F,I,UP,B; line 100)
.venv\Scripts\python.exe -m mypy packora               # types (tests excluded)
.venv\Scripts\python.exe samples\generate_demo.py      # regenerates samples/demo.pcap (committed, 24 packets)
```

- Dev deps live in the `dev` extra (pytest, pytest-cov, pytest-asyncio, ruff, mypy). `scapy` and `textual` are runtime deps.
- CLI sanity: `.venv\Scripts\packora.exe --replay samples/demo.pcap --no-tui`, `--version`, `--list-interfaces`.

## Architecture lines that actually matter

- **scapy may only be imported inside `packora/capture/`.** Parsers emit `models/packet.PacketInfo`; analysis and UI layers must never see scapy types (this is what makes tests run without root/Npcap).
- **Classification contract (F2.1):** every frame yields exactly one `parsed` / `unsupported` / `malformed` `PacketInfo`; `parse_frame` never raises and never returns None. Keep it that way — one bad capture never terminates a run.
- **Testing** uses hand-built raw frames in `tests/conftest.py` (no scapy) plus the committed `samples/demo.pcap`. CI expectation: pytest + ruff + mypy green on Windows and Ubuntu.
- The two parsers' checksums are unused (never validated); conftest leaves them 0.

## Gotchas (each one cost real debugging time)

- **scapy cold import is slow (~2–4s)** and happens inside the capture thread. UI tests must wait for `controller.total > 0` instead of fixed asserts; don't "optimize" this away.
- **Textual REPL details:** `DataTable.clear()` erases columns too — call `clear(columns=False)` to keep headers; `on_data_table_row_selected` handles Enter (the table itself consumes it); when a modal screen is pushed to `Screen`, `app.query_one("#id")` cannot find default-screen widgets (see `[id]` widget refs cached in `on_mount`).
- **Where Enter goes:** a focused `Input` swallows every key; the dashboard focuses the `DataTable` on mount for that reason. If bindings appear dead, check focus first.
- **Numbers in TCP:** DNS-over-TCP framing (2-byte length prefix) is intentionally out of scope — TCP 53 packets get a note, not a decode.
- **`samples/demo.pcap` must match `generate_demo.py`** (the controller test asserts the packet count 24 exactly). If you regenerate, re-run tests.

## Preferences

- Tooling is PowerShell on Windows; prefer `python -m` invocations over bare scripts.
- Summaries are deliberately ASCII (`->`, no unicode arrows) for Windows console safety.
- PRD §10 decisions are settled: packora naming, Python 3.11+, no persistent traffic storage, thresholds via CLI args, PyPI deferred.
