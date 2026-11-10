"""Packora command line entry point (PRD F6).

Examples:
    packora --replay samples/demo.pcap              # TUI over a capture file
    packora --replay samples/demo.pcap --no-tui     # plain summaries to stdout
    packora --list-interfaces
    packora --interface "Ethernet 2" --filter "tcp port 443"

Authorized networks only. Capturing traffic on networks you do not own or
operate may be illegal; Packora is an educational tool (PRD N7).
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

import packora
from packora import reporting
from packora.analysis.analyzers import default_analyzers
from packora.analysis.controller import Controller

EPILOG = """\
examples:
  packora --replay samples/demo.pcap              terminal dashboard over a capture file
  packora --replay samples/demo.pcap --no-tui     plain packet summaries to stdout
  packora --list-interfaces                       enumerate capture interfaces
  packora --interface "Ethernet 2" --filter "tcp port 443"

authorized networks only: capturing traffic on networks you do not own or
operate may be illegal. Packora exists to teach, not to spy. (PRD N7)
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packora",
        description="Educational terminal packet analyzer (mini-Wireshark for the terminal).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"packora {packora.__version__}")
    parser.add_argument(
        "--replay", metavar="FILE.pcap", help="read packets from a capture file instead of live traffic"
    )
    parser.add_argument(
        "--replay-speed",
        type=float,
        default=0.0,
        metavar="X",
        help="replay pacing multiplier: 0 = as fast as possible, 1 = capture rate, 2 = 2x",
    )
    parser.add_argument("--interface", metavar="NAME", help="live capture interface (see --list-interfaces)")
    parser.add_argument("--filter", metavar="BPF", help="BPF capture filter, e.g. \"tcp port 443\"")
    parser.add_argument("--count", type=int, metavar="N", help="stop after N packets")
    parser.add_argument("--no-tui", action="store_true", help="plain stdout output instead of the dashboard")
    parser.add_argument("--no-detect", action="store_true", help="disable the analyzers (port scan, SYN flood, DNS)")
    parser.add_argument("--scan-threshold", type=int, default=10, metavar="N", help="port-scan threshold (default 10)")
    parser.add_argument("--flood-threshold", type=int, default=100, metavar="N", help="SYN-flood threshold (default 100)")
    parser.add_argument("--dns-threshold", type=int, default=100, metavar="N", help="DNS-anomaly threshold (default 100)")
    parser.add_argument(
        "--export-summary", metavar="FILE.json", help="write a machine-readable run summary to this file"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true", help="show available capture interfaces and exit"
    )
    return parser


def _print_interfaces() -> None:
    from packora.capture.live import list_interfaces

    rows = list_interfaces()
    if not rows:
        print("No capture interfaces found.")
        print("Windows: install Npcap (https://npcap.com/) and run this terminal as Administrator.")
        print("Linux: install libpcap and use sudo for capture-capable protocols.")
        return
    name_width = max(len(name) for name, _ in rows)
    print(f"{'interface'.ljust(name_width)}  address")
    print(f"{'-' * name_width}  {'- ' * 4}")
    for name, address in rows:
        print(f"{name.ljust(name_width)}  {address}")


def _make_feed(args: argparse.Namespace) -> tuple[Any, str]:
    if args.replay:
        from packora.capture.replay import ReplayFeed

        return ReplayFeed(args.replay, speed=args.replay_speed), "replay"
    from packora.capture.live import LiveCapture

    feed = LiveCapture(
        iface=args.interface,
        bpf_filter=args.filter,
        count=args.count,
    )
    return feed, "live"


def _run_no_tui(feed: Any, args: argparse.Namespace) -> int:
    """Plain stdout mode: one line per packet (PRD F5.7) plus live alerts."""
    started_wall = time.time()
    analyzers = None if args.no_detect else default_analyzers(
        scan_threshold=args.scan_threshold,
        flood_threshold=args.flood_threshold,
        dns_threshold=args.dns_threshold,
    )
    controller = Controller(feed, analyzers=analyzers)  # type: ignore[arg-type]
    seen_alerts = 0
    error: str | None = None
    last_ts: float | None = None
    try:
        for frame in feed.frames():  # type: ignore[attr-defined]
            if args.count and controller.total >= args.count:
                break
            pkt = controller.process(frame)
            last_ts = frame.ts
            print(pkt.one_liner())
            while len(controller.alerts) > seen_alerts:
                reporting.print_alert_line(controller.alerts[seen_alerts])
                seen_alerts += 1
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # noqa: BLE001 - friendly CLI errors (PRD N1)
        error = str(exc)
        print(f"error: {error}", file=sys.stderr)
    finally:
        controller.stop_thread()
        controller.finalize_analyzers(last_ts)
        # A failed feed ends iteration cleanly with a stored error (e.g. missing
        # Npcap); surface it here rather than leaving an empty run unexplained (N1).
        if error is None:
            error = getattr(feed, "error", None)
            if error:
                print(f"error: {error}", file=sys.stderr)
    _emit_summary(controller, args, started_wall)
    return 1 if error else 0


def _emit_summary(controller: Controller, args: argparse.Namespace, started_wall: float) -> None:
    """Print and optionally export a truthful run summary for either UI mode."""
    summary = reporting.run_summary_text(
        mode="replay" if args.replay else "live",
        target=controller.description(),
        filter_expr=args.filter,
        packets=list(controller.recent),
        alerts=list(controller.alerts),
        started_wall=started_wall,
        detect_enabled=not args.no_detect,
        total_packets=controller.total,
        protocol_mix=controller.stats.mix(),
    )
    print(summary)
    if args.export_summary:
        with open(args.export_summary, "w", encoding="utf-8") as handle:  # noqa: PTH123
            handle.write(
                reporting.run_summary_json(
                    mode="replay" if args.replay else "live",
                    target=controller.description(),
                    filter_expr=args.filter,
                    packets=list(controller.recent),
                    alerts=list(controller.alerts),
                    started_wall=started_wall,
                    detect_enabled=not args.no_detect,
                    total_packets=controller.total,
                    protocol_mix=controller.stats.mix(),
                )
            )
        print(f"summary written to {args.export_summary}")
def _run_tui(feed: Any, args: argparse.Namespace) -> int:
    from packora.ui.app import PackoraApp

    analyzers = None if args.no_detect else default_analyzers(
        scan_threshold=args.scan_threshold,
        flood_threshold=args.flood_threshold,
        dns_threshold=args.dns_threshold,
    )
    controller = Controller(feed, analyzers=analyzers, max_packets=args.count)  # type: ignore[arg-type]
    app = PackoraApp(controller)  # type: ignore[arg-type]
    started_wall = time.time()
    try:
        app.run()
    finally:
        controller.stop_thread()
    _emit_summary(controller, args, started_wall)
    return 1 if controller.error else 0


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "list_interfaces", False):
        _print_interfaces()
        return
    if not args.replay and not args.interface:
        parser.print_usage()
        print("packora: provide --replay FILE.pcap or --interface NAME (see --list-interfaces)", file=sys.stderr)
        raise SystemExit(2)
    feed, _mode = _make_feed(args)
    if args.no_tui:
        raise SystemExit(_run_no_tui(feed, args))
    raise SystemExit(_run_tui(feed, args))


if __name__ == "__main__":
    main()
