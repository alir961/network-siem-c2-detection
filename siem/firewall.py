"""
Active response: block offending IPs with iptables.

Safety rules:
- only the alert's `offender` (the external party) is ever blocked
- internal / whitelisted addresses are never blocked, so the SIEM cannot cut
  the host off from its own gateway or DNS resolver
- each IP is blocked once (rules are checked with `iptables -C` before insert)
"""
from __future__ import annotations

import ipaddress
import subprocess

from .config import WHITELIST_IPS
from .rules import is_internal

BLOCKING_SEVERITIES = ("HIGH", "CRITICAL")


class Firewall:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.blocked: set[str] = set()

    def should_block(self, alert: dict) -> str | None:
        ip = alert.get("offender")
        if not ip or alert["severity"] not in BLOCKING_SEVERITIES:
            return None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        if ip in self.blocked or ip in WHITELIST_IPS or is_internal(ip):
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
