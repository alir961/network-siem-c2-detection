"""
Detection engine — G-SEC-910 Hôpital Mandé SIEM.
R01 C2_DIRECT_HIT / R02 C2_BEACON / R03 C2_EXFIL_VOLUME /
R04 C2_SUSPICIOUS_PORT / R05 DNS_HIGH_RATE / R06 DNS_DGA_SUSPECT /
R07 PORT_SCAN / R08 ICMP_DATA_TUNNEL / R09 HTTP_C2_PATTERN
"""
from __future__ import annotations

import ipaddress
import math
import time
from collections import defaultdict, deque
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest

from .config import (
    C2_IPS, C2_DOMAINS, C2_PORTS, C2_ENDPOINTS,
    INTERNAL_SUBNETS, WHITELIST_IPS, THRESHOLDS,
)


class DetectionEngine:
    def __init__(self) -> None:
        # R02 — beaconing tracker : dst_ip → deque of connection timestamps
        self._beacon: dict[str, deque] = defaultdict(lambda: deque(maxlen=30))

        # R03 — exfil tracker : dst_ip → total bytes sent
        self._exfil_bytes: dict[str, int] = defaultdict(int)
        self._exfil_reset: dict[str, float] = defaultdict(float)

        # R05 — DNS rate tracker
        self._dns_ts: deque = deque(maxlen=500)

        # R07 — port scan tracker : src_ip → {(dst_ip, dst_port)} + first_seen
        self._scan_ports: dict[str, set] = defaultdict(set)
        self._scan_first:  dict[str, float] = {}

    # ────────────────────────────────────────────────────────────────────────

    def analyze(self, pkt) -> list[dict]:
        if not pkt.haslayer(IP):
            return []

        alerts: list[dict] = []
        src: str = pkt[IP].src
        dst: str = pkt[IP].dst
        now: float = time.monotonic()

        # Skip loopback and whitelisted
        if src == "127.0.0.1" or src in WHITELIST_IPS:
            return []

        # ── R01 — C2 direct hit ─────────────────────────────────────────────
        if dst in C2_IPS:
            proto_name = self._proto_name(pkt)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            alerts.append(self._mk("C2_DIRECT_HIT", "CRITICAL", src, dst, {
                "c2_ip":   dst,
                "c2_port": dport,
                "proto":   proto_name,
                "note":    "Known C2 server goog1e.eu (116.202.5.225)",
            }))

        # ── R02 — beaconing ─────────────────────────────────────────────────
        if not self._is_internal(dst) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            ts_q = self._beacon[dst]
            ts_q.append(now)
            n = THRESHOLDS["beaconing_min_count"]
            # Only consider timestamps within the observation window
            window = THRESHOLDS["beaconing_window_sec"]
            recent = [t for t in ts_q if t >= now - window]
            if len(recent) >= n:
                intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
                if intervals:
                    avg = sum(intervals) / len(intervals)
                    variance = sum((x - avg)**2 for x in intervals) / len(intervals)
                    min_iv = THRESHOLDS["beaconing_min_interval"]
                    if (avg >= min_iv
                            and variance < THRESHOLDS["beaconing_variance_max"]
                            and avg <= window / 2):
                        alerts.append(self._mk("C2_BEACON", "HIGH", src, dst, {
                            "avg_interval_sec": round(avg, 2),
                            "variance":         round(variance, 4),
                            "sample_count":     len(recent),
                        }))

        # ── R03 — exfiltration volume ────────────────────────────────────────
        if not self._is_internal(dst):
            payload_len = len(bytes(pkt[IP].payload)) if pkt.haslayer(IP) else 0
            # Reset counter after window
            if now - self._exfil_reset[dst] > 300:
                self._exfil_bytes[dst] = 0
                self._exfil_reset[dst] = now
            self._exfil_bytes[dst] += payload_len
            if self._exfil_bytes[dst] > THRESHOLDS["exfil_bytes_threshold"]:
                alerts.append(self._mk("C2_EXFIL_VOLUME", "CRITICAL", src, dst, {
                    "total_bytes": self._exfil_bytes[dst],
                    "threshold":   THRESHOLDS["exfil_bytes_threshold"],
                }))
                self._exfil_bytes[dst] = 0  # reset to avoid spam

        # ── R04 — suspicious outbound port ──────────────────────────────────
        if pkt.haslayer(TCP) and not self._is_internal(dst):
            dport = pkt[TCP].dport
            if dport in THRESHOLDS["suspicious_ports"]:
                alerts.append(self._mk("C2_SUSPICIOUS_PORT", "HIGH", src, dst, {
                    "dport": dport,
                    "flags": str(pkt[TCP].flags),
                }))

        # ── R05 — DNS high rate ──────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = self._decode_dns(pkt[DNSQR].qname)
            self._dns_ts.append(now)
            cutoff = now - THRESHOLDS["dns_rate_window_sec"]
            while self._dns_ts and self._dns_ts[0] < cutoff:
                self._dns_ts.popleft()
            if len(self._dns_ts) > THRESHOLDS["dns_rate_threshold"]:
                alerts.append(self._mk("DNS_HIGH_RATE", "HIGH", src, dst, {
                    "count_per_min": len(self._dns_ts),
                    "last_query":    qname,
                }))

            # ── R06 — DGA suspect ────────────────────────────────────────────
            label = qname.split(".")[0] if qname else ""
            if (len(label) >= THRESHOLDS["dga_min_label_length"]
                    and self._entropy(label) >= THRESHOLDS["dga_entropy_threshold"]):
                alerts.append(self._mk("DNS_DGA_SUSPECT", "CRITICAL", src, dst, {
                    "domain":  qname,
                    "label":   label,
                    "entropy": round(self._entropy(label), 3),
                }))

        # ── R07 — port scan ──────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            key = f"{src}"
            if key not in self._scan_first:
                self._scan_first[key] = now
            # Reset window
            if now - self._scan_first[key] > THRESHOLDS["port_scan_window_sec"]:
                self._scan_ports[key] = set()
                self._scan_first[key] = now
            self._scan_ports[key].add((dst, dport))
            if len(self._scan_ports[key]) > THRESHOLDS["port_scan_threshold"]:
                alerts.append(self._mk("PORT_SCAN", "HIGH", src, dst, {
                    "unique_dst_ports": len(self._scan_ports[key]),
                    "window_sec":       round(now - self._scan_first[key], 1),
                }))
                self._scan_ports[key] = set()

        # ── R08 — ICMP data tunnel ───────────────────────────────────────────
        if pkt.haslayer(ICMP):
            payload_size = len(bytes(pkt[ICMP].payload))
            if payload_size > THRESHOLDS["icmp_payload_threshold"]:
                alerts.append(self._mk("ICMP_DATA_TUNNEL", "HIGH", src, dst, {
                    "payload_bytes": payload_size,
                    "threshold":     THRESHOLDS["icmp_payload_threshold"],
                }))

        # ── R09 — HTTP C2 endpoint pattern ──────────────────────────────────
        if pkt.haslayer(HTTPRequest):
            method = pkt[HTTPRequest].Method.decode(errors="replace") if pkt[HTTPRequest].Method else ""
            path   = pkt[HTTPRequest].Path.decode(errors="replace")   if pkt[HTTPRequest].Path   else ""
            host   = pkt[HTTPRequest].Host.decode(errors="replace")   if pkt[HTTPRequest].Host   else ""
            ua     = (pkt[HTTPRequest].User_Agent or b"").decode(errors="replace")

            is_c2_host    = any(d in host for d in C2_DOMAINS) or dst in C2_IPS
            is_c2_path    = any(path.endswith(ep) for ep in C2_ENDPOINTS)
            is_c2_ua      = "curl/" in ua

            if is_c2_host or (is_c2_path and method == "POST") or (is_c2_ua and not self._is_internal(dst)):
                severity = "CRITICAL" if (is_c2_host or is_c2_path) else "MEDIUM"
                alerts.append(self._mk("HTTP_C2_PATTERN", severity, src, dst, {
                    "method":      method,
                    "host":        host,
                    "path":        path,
                    "user_agent":  ua[:80],
                    "c2_host_hit": is_c2_host,
                    "c2_path_hit": is_c2_path,
                }))

        return alerts

    # ── Private helpers ──────────────────────────────────────────────────────

    def _is_internal(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in ipaddress.ip_network(net) for net in INTERNAL_SUBNETS)
        except ValueError:
            return False

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        from collections import Counter
        freq = Counter(s)
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())

    @staticmethod
    def _decode_dns(raw) -> str:
        if isinstance(raw, bytes):
            return raw.decode(errors="replace").rstrip(".")
        return str(raw).rstrip(".")

    @staticmethod
    def _proto_name(pkt) -> str:
        if pkt.haslayer(TCP):  return "TCP"
        if pkt.haslayer(UDP):  return "UDP"
        if pkt.haslayer(ICMP): return "ICMP"
        return "IP"

    @staticmethod
    def _mk(rule: str, severity: str, src: str, dst: str, details: dict) -> dict:
        return {"rule": rule, "severity": severity, "src": src, "dst": dst, "details": details}
