"""
Scapy packet capture loop with detection and optional active blocking.
"""
from __future__ import annotations

import subprocess
import time
from typing import Optional

from scapy.all import sniff, conf as scapy_conf

from .rules import DetectionEngine
from .alert import AlertDispatcher
from .logger import SIEMLogger
from .config import THRESHOLDS


class SIEMCapture:
    def __init__(
        self,
        interface:    str,
        engine:       DetectionEngine,
        dispatcher:   AlertDispatcher,
        logger:       SIEMLogger,
        block_mode:   bool = False,
        verbose:      bool = True,
    ) -> None:
        self._iface      = interface
        self._engine     = engine
        self._dispatcher = dispatcher
        self._logger     = logger
        self._block      = block_mode
        self._verbose    = verbose

        # Deduplication : rule:src:dst → last_alert timestamp
        self._dedup: dict[str, float] = {}

    # ─────────────────────────────────────────────────────────────────────────

    def start(self, packet_filter: str = "") -> None:
        scapy_conf.verb = 0
        print(f"[SIEM] Starting on interface '{self._iface}'"
              f"{' (BLOCK mode)' if self._block else ''}")
        print(f"[SIEM] Log file: {self._logger._path}")
        sniff(iface=self._iface, prn=self._process, store=False,
              filter=packet_filter or None)

    # ─────────────────────────────────────────────────────────────────────────

    def _process(self, pkt) -> None:
        alerts = self._engine.analyze(pkt)
        for alert in alerts:
            if not self._should_emit(alert):
                continue

            entry = self._logger.log(
                alert["rule"],
                alert["severity"],
                alert["src"],
                alert["dst"],
                alert["details"],
            )
            self._dispatcher.send(entry)

            if self._verbose:
                print(
                    f"[{entry['timestamp']}] [{entry['severity']:8s}] "
                    f"{entry['rule']:<22} {entry['src']:>15} -> {entry['dst']}"
                )

            if self._block and alert["severity"] in ("HIGH", "CRITICAL"):
                self._block_ip(alert["dst"])

    def _should_emit(self, alert: dict) -> bool:
        key = f"{alert['rule']}:{alert['src']}:{alert['dst']}"
        now = time.monotonic()
        last = self._dedup.get(key, 0.0)
        if now - last < THRESHOLDS["alert_dedup_window_sec"]:
            return False
        self._dedup[key] = now
        return True

    def _block_ip(self, ip: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            print(f"[BLOCK] iptables DROP <-> {ip}")
        except subprocess.CalledProcessError as exc:
            print(f"[BLOCK ERROR] {exc.stderr.decode().strip()}")
        except FileNotFoundError:
            print("[BLOCK ERROR] iptables not found — are you root?")
