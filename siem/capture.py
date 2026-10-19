"""
Packet pipeline: capture (live or pcap replay) → detection → dedup → log / alert / block.
"""
from __future__ import annotations

import time

from scapy.all import PcapReader, sniff
from scapy.all import conf as scapy_conf

from .alert import AlertDispatcher
from .config import THRESHOLDS
from .firewall import Firewall
from .logger import SIEMLogger
from .rules import DetectionEngine


class SIEMCapture:
    def __init__(
        self,
        engine: DetectionEngine,
        dispatcher: AlertDispatcher,
        logger: SIEMLogger,
        firewall: Firewall | None = None,
        verbose: bool = True,
    ) -> None:
        self._engine = engine
        self._dispatcher = dispatcher
        self._logger = logger
        self._firewall = firewall
        self._verbose = verbose
        self._dedup: dict[str, float] = {}
        self.stats: dict[str, int] = {"packets": 0, "alerts": 0, "suppressed": 0}

    # ─────────────────────────────────────────────────────────────────────────

    def live(self, interface: str, packet_filter: str = "") -> None:
        scapy_conf.verb = 0
        sniff(iface=interface, prn=self.process, store=False, filter=packet_filter or None)

    def replay(self, pcap_path: str) -> None:
        """Run a capture file through the engine, using the packets' own timestamps."""
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                self.process(pkt, now=float(pkt.time))

    # ─────────────────────────────────────────────────────────────────────────

    def process(self, pkt, now: float | None = None) -> None:
        replay = now is not None
        if now is None:
            now = time.monotonic()
        self.stats["packets"] += 1

        for alert in self._engine.analyze(pkt, now=now):
            if not self._should_emit(alert, now):
                self.stats["suppressed"] += 1
                continue
            self.stats["alerts"] += 1

            entry = self._logger.log(alert, epoch=now if replay else None)
            self._dispatcher.send(entry)

            if self._verbose or alert["severity"] == "CRITICAL":
                print(f"[{entry['timestamp']}] [{entry['severity']:<8}] "
                      f"{entry['rule']:<20} {entry['src']:>15} -> {entry['dst']:<15} "
                      f"{_short(entry['details'])}")

            if self._firewall:
                ip = self._firewall.should_block(alert)
                if ip and self._firewall.block(ip):
                    mode = " (dry run)" if self._firewall.dry_run else ""
                    print(f"{'':>24}[BLOCK] iptables DROP in/out {ip}{mode}")

    def _should_emit(self, alert: dict, now: float) -> bool:
        window = THRESHOLDS["alert_dedup_window_sec"]
        key = f"{alert['rule']}:{alert['src']}:{alert['dst']}"
        if now - self._dedup.get(key, float("-inf")) < window:
            return False
        self._dedup[key] = now
        if len(self._dedup) > 10_000:  # keep memory bounded on long runs
            self._dedup = {k: t for k, t in self._dedup.items() if now - t < window}
        return True


def _short(details: dict) -> str:
    text = " ".join(f"{k}={v}" for k, v in details.items() if k != "user_agent")
    return text if len(text) <= 100 else text[:99] + "…"
