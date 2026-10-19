"""
Unit tests for the SIEM detection engine.
Tests run without a live network interface using crafted Scapy packets.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from siem.rules import DetectionEngine


def _engine():
    return DetectionEngine()


# ── R01 — C2 Direct Hit ─────────────────────────────────────────────────────

def test_c2_direct_hit_tcp():
    e = _engine()
    pkt = IP(src="192.168.5.3", dst="116.202.5.225") / TCP(dport=80)
    alerts = e.analyze(pkt)
    rules = [a["rule"] for a in alerts]
    assert "C2_DIRECT_HIT" in rules, "Should detect C2 direct hit"


def test_c2_direct_hit_severity():
    e = _engine()
    pkt = IP(src="192.168.5.3", dst="116.202.5.225") / TCP(dport=80)
    alerts = {a["rule"]: a for a in e.analyze(pkt)}
    assert alerts["C2_DIRECT_HIT"]["severity"] == "CRITICAL"


def test_no_alert_internal_traffic():
    e = _engine()
    pkt = IP(src="192.168.5.3", dst="192.168.5.1") / TCP(dport=443)
    alerts = e.analyze(pkt)
    # No C2 hit for internal traffic
    assert not any(a["rule"] == "C2_DIRECT_HIT" for a in alerts)


# ── R04 — Suspicious Port ────────────────────────────────────────────────────

def test_reverse_shell_port_4444():
    e = _engine()
    pkt = IP(src="192.168.5.3", dst="1.2.3.4") / TCP(dport=4444, flags="S")
    alerts = e.analyze(pkt)
    assert any(a["rule"] == "C2_SUSPICIOUS_PORT" for a in alerts)


def test_port_1337():
    e = _engine()
    pkt = IP(src="192.168.5.3", dst="5.6.7.8") / TCP(dport=1337, flags="S")
    alerts = e.analyze(pkt)
    assert any(a["rule"] == "C2_SUSPICIOUS_PORT" for a in alerts)


def test_normal_port_443_no_alert():
    e = _engine()
    pkt = IP(src="192.168.5.3", dst="1.2.3.4") / TCP(dport=443, flags="S")
    alerts = e.analyze(pkt)
    assert not any(a["rule"] == "C2_SUSPICIOUS_PORT" for a in alerts)


# ── R06 — DNS DGA ────────────────────────────────────────────────────────────

def test_dga_high_entropy_domain():
    e = _engine()
    # High entropy domain label (random-looking)
    pkt = (IP(src="192.168.5.3", dst="8.8.8.8") / UDP(dport=53)
           / DNS(rd=1, qd=DNSQR(qname="xk7qp9m3bvzw1.evil.com")))
    alerts = e.analyze(pkt)
    assert any(a["rule"] == "DNS_DGA_SUSPECT" for a in alerts), \
        "High entropy domain should trigger DGA alert"


def test_legit_domain_no_dga():
    e = _engine()
    pkt = (IP(src="192.168.5.3", dst="8.8.8.8") / UDP(dport=53)
           / DNS(rd=1, qd=DNSQR(qname="google.com")))
    alerts = e.analyze(pkt)
    assert not any(a["rule"] == "DNS_DGA_SUSPECT" for a in alerts), \
        "Legitimate domain should not trigger DGA"


# ── R08 — ICMP Tunnel ────────────────────────────────────────────────────────

def test_icmp_data_tunnel():
    e = _engine()
    payload = b"A" * 200  # 200 bytes >> 64 threshold
    pkt = IP(src="192.168.5.3", dst="1.2.3.4") / ICMP() / Raw(load=payload)
    alerts = e.analyze(pkt)
    assert any(a["rule"] == "ICMP_DATA_TUNNEL" for a in alerts)


def test_small_icmp_no_alert():
    e = _engine()
    pkt = IP(src="192.168.5.3", dst="1.2.3.4") / ICMP() / Raw(load=b"ping")
    alerts = e.analyze(pkt)
    assert not any(a["rule"] == "ICMP_DATA_TUNNEL" for a in alerts)


# ── R02 — Beaconing ──────────────────────────────────────────────────────────

def test_beaconing_detection():
    import time
    e = _engine()
    dst = "116.202.5.225"
    # Inject 6 recent timestamps at ~30s intervals (relative to now)
    now = time.monotonic()
    e._beacon[dst].extend([now - 150, now - 120, now - 90, now - 60, now - 30])
    pkt = IP(src="192.168.5.3", dst=dst) / TCP(dport=80)
    alerts = e.analyze(pkt)
    assert any(a["rule"] == "C2_BEACON" for a in alerts)


if __name__ == "__main__":
    # Simple test runner without pytest dependency
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {fn.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
