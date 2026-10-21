"""
Active response: block offending IPs with iptables.

Safety rules:
- only the alert's `offender` (the external party) is ever blocked
- internal / whitelisted addresses are never blocked, nor the host's DNS
  resolvers or any address in SIEM_NEVER_BLOCK, so the SIEM cannot cut the
  host off from its gateway or DNS even when a scan's source is forged
- each IP is blocked once (rules are checked with `iptables -C` before insert)
"""
from __future__ import annotations

import ipaddress
import subprocess

from .config import NEVER_BLOCK_IPS, WHITELIST_IPS
from .rules import is_internal

BLOCKING_SEVERITIES = ("HIGH", "CRITICAL")


class Firewall:
    def __init__(self, dry_run: bool = False, never_block: set[str] | None = None) -> None:
        self.dry_run = dry_run
        self.blocked: set[str] = set()
        self.never_block = NEVER_BLOCK_IPS if never_block is None else never_block

    def should_block(self, alert: dict) -> str | None:
        ip = alert.get("offender")
        if not ip or alert["severity"] not in BLOCKING_SEVERITIES:
            return None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        if ip in self.blocked or ip in WHITELIST_IPS or ip in self.never_block or is_internal(ip):
            return None
        return ip

    def block(self, ip: str) -> bool:
        """Drop all traffic to and from `ip`. Returns True if a new block was applied."""
        rules = (["OUTPUT", "-d", ip, "-j", "DROP"], ["INPUT", "-s", ip, "-j", "DROP"])
        if self.dry_run:
            self.blocked.add(ip)
            return True
        try:
            for rule in rules:
                exists = subprocess.run(["iptables", "-C", *rule], capture_output=True).returncode == 0
                if not exists:
                    subprocess.run(["iptables", "-I", *rule], check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            print(f"[BLOCK ERROR] {exc.stderr.decode().strip()}")
            return False
        except FileNotFoundError:
            print("[BLOCK ERROR] iptables not found")
            return False
        self.blocked.add(ip)
        return True
