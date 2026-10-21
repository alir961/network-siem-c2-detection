"""
Detection engine.

R01 C2_DIRECT_HIT       traffic to a known C2 IP, or a lookup of a C2 domain
R02 C2_BEACON           outbound connections repeating at a regular interval
R03 C2_EXFIL_VOLUME     large outbound volume to one external host
R04 C2_SUSPICIOUS_PORT  outbound connection to a common reverse-shell port
R05 DNS_HIGH_RATE       abnormal DNS query rate (DGA / tunnelling)
R06 DNS_DGA_SUSPECT     high-entropy domain label
R07 PORT_SCAN           one source probing many ports on one host
R08 ICMP_DATA_TUNNEL    ICMP echo carrying an oversized payload
R09 HTTP_C2_PATTERN     HTTP request matching the C2 host / endpoints / user-agent

Every alert carries an `offender`: the external party the alert is about,
which is what active blocking acts on (never the protected host itself).
"""
from __future__ import annotations

import ipaddress
import math
import time
from collections import Counter, defaultdict, deque

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP

from .config import DEFAULT_IOCS, INTERNAL_SUBNETS, THRESHOLDS, WHITELIST_IPS, IOCs

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in INTERNAL_SUBNETS]
PRUNE_INTERVAL_SEC = 10.0


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


class DetectionEngine:
    def __init__(self, iocs: IOCs | None = None, thresholds: dict | None = None) -> None:
        self.iocs = iocs or DEFAULT_IOCS
        self.t = {**THRESHOLDS, **(thresholds or {})}

        # R02: dst_ip -> timestamps of new connections
        self._beacon: dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        # R03: dst_ip -> sliding window of (timestamp, bytes)
        self._exfil: dict[str, deque] = defaultdict(deque)
        self._exfil_total: dict[str, int] = defaultdict(int)
        # R05: timestamps of DNS queries
        self._dns_ts: deque = deque(maxlen=1000)
        # R07: (src, dst) -> [set of ports, window_start]
        self._scan: dict[tuple[str, str], list] = {}
        self._last_prune = 0.0

    # ────────────────────────────────────────────────────────────────────────

    def analyze(self, pkt, now: float | None = None) -> list[dict]:
        """Return the alerts raised by one packet.

        `now` lets callers replay captures with their original timing;
        live capture uses the monotonic clock.
        """
        if not pkt.haslayer(IP):
            return []
        if now is None:
            now = time.monotonic()
        if now - self._last_prune >= PRUNE_INTERVAL_SEC:
            self._prune(now)

        src: str = pkt[IP].src
        dst: str = pkt[IP].dst
        if src.startswith("127.") or src in WHITELIST_IPS or dst in WHITELIST_IPS:
            return []

        outbound = not is_internal(dst)
        alerts: list[dict] = []

        tcp = pkt[TCP] if pkt.haslayer(TCP) else None
        syn_only = tcp is not None and "S" in tcp.flags and "A" not in tcp.flags
        new_flow = syn_only or (pkt.haslayer(UDP) and not pkt.haslayer(DNS))

        # R01: C2 direct hit
        if dst in self.iocs.c2_ips or src in self.iocs.c2_ips:
            c2 = dst if dst in self.iocs.c2_ips else src
            alerts.append(self._mk("C2_DIRECT_HIT", "CRITICAL", src, dst, c2, {
                "c2_ip": c2,
                "port": self._dport(pkt),
                "proto": self._proto_name(pkt),
                "direction": "outbound" if c2 == dst else "inbound",
            }))

        # R02: beaconing, measured on new connections, not on every packet of a stream
        if outbound and new_flow:
            ts_q = self._beacon[dst]
            ts_q.append(now)
            window = self.t["beaconing_window_sec"]
            recent = [t for t in ts_q if t >= now - window]
            if len(recent) >= self.t["beaconing_min_count"]:
                # Look for a dominant interval: other connections to the same host
                # (uploads, updates) must not hide an otherwise regular heartbeat.
                intervals = sorted(b - a for a, b in zip(recent, recent[1:], strict=False))
                median = intervals[len(intervals) // 2]
                tolerance = max(1.0, median * self.t["beaconing_jitter_ratio"])
                regular = [x for x in intervals if abs(x - median) <= tolerance]
                if (median >= self.t["beaconing_min_interval"]
                        and len(regular) >= self.t["beaconing_min_count"] - 1):
                    alerts.append(self._mk("C2_BEACON", "HIGH", src, dst, dst, {
                        "interval_sec": round(median, 2),
                        "regular_intervals": len(regular),
                        "connections": len(recent),
                    }))

        # R03: exfiltration volume over a sliding window
        if outbound:
            size = len(bytes(pkt[IP].payload))
            win = self._exfil[dst]
            win.append((now, size))
            self._exfil_total[dst] += size
            while win and win[0][0] < now - self.t["exfil_window_sec"]:
                self._exfil_total[dst] -= win.popleft()[1]
            if self._exfil_total[dst] > self.t["exfil_bytes_threshold"]:
                alerts.append(self._mk("C2_EXFIL_VOLUME", "CRITICAL", src, dst, dst, {
                    "bytes": self._exfil_total[dst],
                    "window_sec": self.t["exfil_window_sec"],
                }))
                win.clear()
                self._exfil_total[dst] = 0

        # R04: suspicious outbound port
        if syn_only and outbound and tcp.dport in self.t["suspicious_ports"]:
            alerts.append(self._mk("C2_SUSPICIOUS_PORT", "HIGH", src, dst, dst, {
                "dport": tcp.dport,
            }))

        # R05 / R06: DNS (queries only, so responses are not counted twice)
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            qname = self._decode_dns(pkt[DNSQR].qname)
            self._dns_ts.append(now)
            cutoff = now - self.t["dns_rate_window_sec"]
            while self._dns_ts and self._dns_ts[0] < cutoff:
                self._dns_ts.popleft()
            if len(self._dns_ts) > self.t["dns_rate_threshold"]:
                alerts.append(self._mk("DNS_HIGH_RATE", "HIGH", src, dst, None, {
                    "queries_in_window": len(self._dns_ts),
                    "last_query": qname,
                }))

            label = qname.split(".")[0] if qname else ""
            entropy = self._entropy(label)
            if len(label) >= self.t["dga_min_label_length"] and entropy >= self.t["dga_entropy_threshold"]:
                alerts.append(self._mk("DNS_DGA_SUSPECT", "CRITICAL", src, dst, None, {
                    "domain": qname,
                    "entropy": round(entropy, 3),
                }))
            if any(qname == d or qname.endswith("." + d) for d in self.iocs.c2_domains):
                alerts.append(self._mk("C2_DIRECT_HIT", "CRITICAL", src, dst, None, {
                    "c2_domain": qname,
                    "proto": "DNS",
                }))

        # R07: vertical port scan, counted on connection attempts only
        if syn_only:
            key = (src, dst)
            state = self._scan.get(key)
            if state is None or now - state[1] > self.t["port_scan_window_sec"]:
                state = self._scan[key] = [set(), now]
            state[0].add(tcp.dport)
            if len(state[0]) > self.t["port_scan_threshold"]:
                offender = src if not is_internal(src) else None
                alerts.append(self._mk("PORT_SCAN", "HIGH", src, dst, offender, {
                    "unique_ports": len(state[0]),
                    "window_sec": round(now - state[1], 1),
                }))
                self._scan[key] = [set(), now]

        # R08: ICMP data tunnel (echo request / reply only)
        if pkt.haslayer(ICMP) and pkt[ICMP].type in (0, 8):
            payload_size = len(bytes(pkt[ICMP].payload))
            if payload_size > self.t["icmp_payload_threshold"]:
                remote = dst if outbound else (src if not is_internal(src) else None)
                alerts.append(self._mk("ICMP_DATA_TUNNEL", "HIGH", src, dst, remote, {
                    "payload_bytes": payload_size,
                }))

        # R09: HTTP C2 pattern
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            method = (req.Method or b"").decode(errors="replace")
            path = (req.Path or b"").decode(errors="replace")
            host = (req.Host or b"").decode(errors="replace").split(":")[0]
            ua = (req.User_Agent or b"").decode(errors="replace")

            c2_host = host in self.iocs.c2_domains or dst in self.iocs.c2_ips
            c2_path = method == "POST" and any(path.endswith(ep) for ep in self.iocs.c2_endpoints)
            tool_ua = ua.startswith(("curl/", "Wget/", "python-requests/")) and outbound

            if c2_host or c2_path or tool_ua:
                alerts.append(self._mk(
                    "HTTP_C2_PATTERN", "CRITICAL" if (c2_host or c2_path) else "MEDIUM",
                    src, dst, dst if outbound else None, {
                        "method": method,
                        "host": host,
                        "path": path,
                        "user_agent": ua[:80],
                        "c2_host": c2_host,
                        "c2_endpoint": c2_path,
                    },
                ))

        return alerts

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _prune(self, now: float) -> None:
        """Forget hosts whose windows have expired.

        Source addresses can be forged, so without this a flood of random
        sources would grow the per-host state without limit.
        """
        self._last_prune = now
        scan_cutoff = now - self.t["port_scan_window_sec"]
        self._scan = {k: v for k, v in self._scan.items() if v[1] >= scan_cutoff}
        beacon_cutoff = now - self.t["beaconing_window_sec"]
        for ip in [ip for ip, q in self._beacon.items() if not q or q[-1] < beacon_cutoff]:
            del self._beacon[ip]
        exfil_cutoff = now - self.t["exfil_window_sec"]
        for ip in [ip for ip, w in self._exfil.items() if not w or w[-1][0] < exfil_cutoff]:
            del self._exfil[ip]
            self._exfil_total.pop(ip, None)

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in Counter(s).values())

    @staticmethod
    def _decode_dns(raw) -> str:
        if isinstance(raw, bytes):
            return raw.decode(errors="replace").rstrip(".").lower()
        return str(raw).rstrip(".").lower()

    @staticmethod
    def _dport(pkt) -> int:
        if pkt.haslayer(TCP):
            return pkt[TCP].dport
        if pkt.haslayer(UDP):
            return pkt[UDP].dport
        return 0

    @staticmethod
    def _proto_name(pkt) -> str:
        for layer, name in ((TCP, "TCP"), (UDP, "UDP"), (ICMP, "ICMP")):
            if pkt.haslayer(layer):
                return name
        return "IP"

    @staticmethod
    def _mk(rule: str, severity: str, src: str, dst: str, offender: str | None, details: dict) -> dict:
        return {
            "rule": rule, "severity": severity, "src": src, "dst": dst,
            "offender": offender, "details": details,
        }
