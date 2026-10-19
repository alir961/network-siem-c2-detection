"""
Network SIEM: C2, exfiltration and reconnaissance detection with active response.

Usage:
    sudo python -m siem -i eth0 [--block]          # live capture
    python -m siem --pcap capture.pcap              # offline replay, no root needed
"""
from __future__ import annotations

import argparse
import sys

from .alert import AlertDispatcher
from .capture import SIEMCapture
from .config import (
    DEFAULT_IOCS,
    DISCORD_WEBHOOK_URL,
    INTERFACE,
    LOG_FILE,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    IOCs,
)
from .firewall import Firewall
from .logger import SIEMLogger
from .rules import DetectionEngine
from .rules import __doc__ as RULES_DOC


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem",
        description="Network SIEM: C2, exfiltration and reconnaissance detection with active response.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Rules:\n" + "\n".join(
            "  " + line for line in RULES_DOC.splitlines() if line.startswith("R")
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-i", "--interface", default=INTERFACE, help=f"interface to sniff (default: {INTERFACE})")
    source.add_argument("--pcap", help="replay a capture file instead of sniffing live")
    parser.add_argument("--filter", default="", help="BPF filter for live capture (e.g. 'not port 22')")
    parser.add_argument("--iocs", help="JSON file of IOCs (c2_ips, c2_domains, c2_endpoints)")
    parser.add_argument("--block", action="store_true", help="block HIGH/CRITICAL offenders with iptables")
    parser.add_argument("--dry-run", action="store_true", help="with --block: report blocks without touching iptables")
    parser.add_argument("--log", default=LOG_FILE, help=f"JSON Lines alert log (default: {LOG_FILE})")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print CRITICAL alerts")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    iocs = IOCs.from_file(args.iocs) if args.iocs else DEFAULT_IOCS
    dispatcher = AlertDispatcher(DISCORD_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
    firewall = Firewall(dry_run=args.dry_run) if args.block else None
    pipeline = SIEMCapture(
        engine=DetectionEngine(iocs),
        dispatcher=dispatcher,
        logger=SIEMLogger(args.log),
        firewall=firewall,
        verbose=not args.quiet,
    )

    print("=" * 64)
    print(f"  Source    : {'pcap ' + args.pcap if args.pcap else 'interface ' + args.interface}")
    print(f"  IOCs      : {len(iocs.c2_ips)} IPs, {len(iocs.c2_domains)} domains")
    print(f"  Response  : {'iptables block' + (' (dry run)' if args.dry_run else '') if args.block else 'passive'}")
    print(f"  Alerting  : {', '.join(dispatcher.channels) or 'console + log only'}")
    print(f"  Log file  : {args.log}")
    print("=" * 64)

    try:
        if args.pcap:
            pipeline.replay(args.pcap)
        else:
            pipeline.live(args.interface, args.filter)
    except PermissionError:
        print("[ERROR] Live capture needs root (or CAP_NET_RAW). Use --pcap to replay a file.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[SIEM] Stopped.")

    s = pipeline.stats
    print(f"\n[SIEM] {s['packets']} packets, {s['alerts']} alerts ({s['suppressed']} duplicates suppressed)")
    if firewall and firewall.blocked:
        print(f"[SIEM] Blocked: {', '.join(sorted(firewall.blocked))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
