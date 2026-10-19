#!/usr/bin/env python3
"""
G-SEC-910 — Custom SIEM for Hôpital Mandé
Usage:
    sudo python3 -m siem [-i eth0] [--block] [--log /tmp/siem_logs/alerts.jsonl]
"""
import argparse
import sys

from .config import (
    INTERFACE, LOG_FILE,
    DISCORD_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
)
from .capture    import SIEMCapture
from .rules      import DetectionEngine
from .alert      import AlertDispatcher
from .logger     import SIEMLogger


def main() -> None:
    parser = argparse.ArgumentParser(
        description="G-SEC-910 Custom SIEM — Hôpital Mandé",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Rules active:
  R01 C2_DIRECT_HIT    — connexion vers IP/domaine C2 connu (goog1e.eu)
  R02 C2_BEACON        — beaconing régulier vers IP externe
  R03 C2_EXFIL_VOLUME  — volume excessif sortant (exfiltration)
  R04 C2_SUSPICIOUS_PORT — port reverse-shell connu
  R05 DNS_HIGH_RATE    — volume DNS anormal (DGA/tunnel)
  R06 DNS_DGA_SUSPECT  — entropie Shannon élevée sur domaine
  R07 PORT_SCAN        — balayage de ports
  R08 ICMP_DATA_TUNNEL — tunnel ICMP (payload > 64 bytes)
  R09 HTTP_C2_PATTERN  — requête HTTP vers endpoint C2 connu
""",
    )
    parser.add_argument(
        "-i", "--interface",
        default=INTERFACE,
        help=f"Interface réseau à sniffer (défaut: {INTERFACE})",
    )
    parser.add_argument(
        "--block",
        action="store_true",
        help="Mode actif — bloque automatiquement via iptables les IPs HIGH/CRITICAL",
    )
    parser.add_argument(
        "--log",
        default=LOG_FILE,
        help=f"Chemin du fichier de logs JSON (défaut: {LOG_FILE})",
    )
    parser.add_argument(
        "--filter",
        default="",
        help="Filtre BPF Scapy (ex: 'host 116.202.5.225')",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Mode silencieux — n'affiche que les alertes CRITICAL",
    )
    args = parser.parse_args()

    # ── Bootstrap ─────────────────────────────────────────────────────────
    engine     = DetectionEngine()
    dispatcher = AlertDispatcher(
        discord_webhook  = DISCORD_WEBHOOK_URL or None,
        telegram_token   = TELEGRAM_BOT_TOKEN  or None,
        telegram_chat_id = TELEGRAM_CHAT_ID    or None,
    )
    logger  = SIEMLogger(args.log)
    capture = SIEMCapture(
        interface  = args.interface,
        engine     = engine,
        dispatcher = dispatcher,
        logger     = logger,
        block_mode = args.block,
        verbose    = not args.quiet,
    )

    print("=" * 60)
    print("  G-SEC-910 SIEM — Hôpital Mandé")
    print(f"  Interface : {args.interface}")
    print(f"  Log file  : {args.log}")
    print(f"  Block mode: {'YES (iptables)' if args.block else 'NO (passive)'}")
    print(f"  Discord   : {'configured' if DISCORD_WEBHOOK_URL else 'NOT configured'}")
    print(f"  Telegram  : {'configured' if TELEGRAM_BOT_TOKEN else 'NOT configured'}")
    print("=" * 60)

    try:
        capture.start(packet_filter=args.filter)
    except PermissionError:
        print("[ERROR] Permission denied — run as root (sudo)", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[SIEM] Stopped by user.")


if __name__ == "__main__":
    main()
