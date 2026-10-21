"""
Detection engine tests, using crafted Scapy packets (no network or root needed).
"""
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw

from siem.rules import DetectionEngine

HOST = "192.168.5.3"
C2 = "116.202.5.225"


def rules(alerts):
    return {a["rule"] for a in alerts}


def syn(src, dst, dport, sport=40000):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def dns_query(name, src=HOST):
    return IP(src=src, dst="192.168.5.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=name))


# ── R01 C2 direct hit ───────────────────────────────────────────────────────

def test_c2_ip_is_critical_and_blames_c2():
    alert = next(a for a in DetectionEngine().analyze(syn(HOST, C2, 80), now=0) if a["rule"] == "C2_DIRECT_HIT")
    assert alert["severity"] == "CRITICAL"
    assert alert["offender"] == C2


def test_c2_domain_lookup_detected():
    assert "C2_DIRECT_HIT" in rules(DetectionEngine().analyze(dns_query("goog1e.eu"), now=0))
    assert "C2_DIRECT_HIT" in rules(DetectionEngine().analyze(dns_query("api.goog1e.eu"), now=0))


def test_internal_traffic_is_quiet():
    assert DetectionEngine().analyze(syn(HOST, "192.168.5.1", 443), now=0) == []


# ── R02 beaconing ───────────────────────────────────────────────────────────

def test_regular_beacon_detected():
    e = DetectionEngine()
    alerts = [a for i in range(5) for a in e.analyze(syn(HOST, "1.2.3.4", 80, 41000 + i), now=i * 60.0)]
    beacon = next(a for a in alerts if a["rule"] == "C2_BEACON")
    assert beacon["details"]["interval_sec"] == 60.0


def test_beacon_survives_an_extra_connection():
    e = DetectionEngine()
    times = [0, 120, 240, 300, 360, 480]  # 300 = unrelated upload to the same host
    alerts = [a for i, t in enumerate(times) for a in e.analyze(syn(HOST, "1.2.3.4", 80, 41000 + i), now=t)]
    assert "C2_BEACON" in rules(alerts)


def test_irregular_connections_are_not_a_beacon():
    e = DetectionEngine()
    times = [0, 7, 50, 51, 140, 300]
    alerts = [a for i, t in enumerate(times) for a in e.analyze(syn(HOST, "1.2.3.4", 80, 41000 + i), now=t)]
    assert "C2_BEACON" not in rules(alerts)


def test_packets_of_one_stream_are_not_a_beacon():
    e = DetectionEngine()
    pkt = IP(src=HOST, dst="1.2.3.4") / TCP(dport=443, flags="PA") / Raw(b"x" * 10)
    alerts = [a for t in range(0, 600, 10) for a in e.analyze(pkt, now=float(t))]
    assert "C2_BEACON" not in rules(alerts)


# ── R03 exfiltration ────────────────────────────────────────────────────────

def test_exfil_volume_across_window_boundary():
    e = DetectionEngine()
    chunk = IP(src=HOST, dst="1.2.3.4") / TCP(dport=80, flags="PA") / Raw(b"\0" * 1400)
    e.analyze(chunk, now=0.0)  # starts the window
    alerts = [a for i in range(150) for a in e.analyze(chunk, now=299.0 + i * 0.01)]
    assert "C2_EXFIL_VOLUME" in rules(alerts)


def test_slow_trickle_under_threshold():
    e = DetectionEngine()
    chunk = IP(src=HOST, dst="1.2.3.4") / TCP(dport=80, flags="PA") / Raw(b"\0" * 1000)
    alerts = [a for i in range(100) for a in e.analyze(chunk, now=i * 10.0)]
    assert "C2_EXFIL_VOLUME" not in rules(alerts)


# ── R04 suspicious port ─────────────────────────────────────────────────────

def test_reverse_shell_port():
    assert "C2_SUSPICIOUS_PORT" in rules(DetectionEngine().analyze(syn(HOST, "1.2.3.4", 4444), now=0))


def test_https_is_not_suspicious():
    assert "C2_SUSPICIOUS_PORT" not in rules(DetectionEngine().analyze(syn(HOST, "1.2.3.4", 443), now=0))


# ── R05 / R06 DNS ───────────────────────────────────────────────────────────

def test_dga_domain():
    assert "DNS_DGA_SUSPECT" in rules(DetectionEngine().analyze(dns_query("xk7qp9m3bvzw1.evil.com"), now=0))


def test_normal_domain_is_not_dga():
    assert "DNS_DGA_SUSPECT" not in rules(DetectionEngine().analyze(dns_query("google.com"), now=0))


def test_dns_rate():
    e = DetectionEngine()
    alerts = [a for i in range(40) for a in e.analyze(dns_query(f"host{i}.example.com"), now=i * 0.5)]
    assert "DNS_HIGH_RATE" in rules(alerts)


def test_dns_responses_are_not_counted():
    e = DetectionEngine()
    resp = (IP(src="192.168.5.1", dst=HOST) / UDP(sport=53)
            / DNS(qr=1, qd=DNSQR(qname="xk7qp9m3bvzw1.evil.com"), an=DNSRR(rrname="xk7qp9m3bvzw1.evil.com")))
    alerts = [a for i in range(40) for a in e.analyze(resp, now=i * 0.5)]
    assert alerts == []


# ── R07 port scan ───────────────────────────────────────────────────────────

def test_inbound_port_scan_blames_scanner():
    e = DetectionEngine()
    alerts = [a for p in range(1, 30) for a in e.analyze(syn("198.51.100.23", HOST, p), now=p * 0.01)]
    scan = next(a for a in alerts if a["rule"] == "PORT_SCAN")
    assert scan["offender"] == "198.51.100.23"


def test_browsing_many_sites_is_not_a_scan():
    e = DetectionEngine()
    alerts = [a for i in range(50) for a in e.analyze(syn(HOST, f"93.184.216.{i}", 443, 44000 + i), now=i * 0.1)]
    assert "PORT_SCAN" not in rules(alerts)


# ── R08 ICMP tunnel ─────────────────────────────────────────────────────────

def test_icmp_tunnel():
    pkt = IP(src=HOST, dst="1.2.3.4") / ICMP(type=8) / Raw(b"A" * 200)
    assert "ICMP_DATA_TUNNEL" in rules(DetectionEngine().analyze(pkt, now=0))


def test_regular_ping():
    pkt = IP(src=HOST, dst="1.2.3.4") / ICMP(type=8) / Raw(b"\0" * 56)
    assert "ICMP_DATA_TUNNEL" not in rules(DetectionEngine().analyze(pkt, now=0))


# ── R09 HTTP C2 pattern ─────────────────────────────────────────────────────

def http(dst, host, path, method=b"POST", ua=b"Mozilla/5.0"):
    req = HTTPRequest(Method=method, Path=path, Host=host, User_Agent=ua)
    return IP(src=HOST, dst=dst) / TCP(dport=80, flags="PA") / HTTP() / req


def test_c2_endpoint_post():
    alert = next(a for a in DetectionEngine().analyze(http("1.2.3.4", b"cdn.example", b"/beacon"), now=0)
                 if a["rule"] == "HTTP_C2_PATTERN")
    assert alert["severity"] == "CRITICAL"


def test_curl_user_agent_is_medium():
    alerts = DetectionEngine().analyze(http("1.2.3.4", b"example.com", b"/", b"GET", b"curl/8.5.0"), now=0)
    assert any(a["rule"] == "HTTP_C2_PATTERN" and a["severity"] == "MEDIUM" for a in alerts)


def test_normal_browser_request():
    alerts = DetectionEngine().analyze(http("1.2.3.4", b"example.com", b"/index.html", b"GET"), now=0)
    assert "HTTP_C2_PATTERN" not in rules(alerts)


# ── State pruning ───────────────────────────────────────────────────────────

def test_state_of_forged_sources_is_forgotten():
    e = DetectionEngine()
    for i in range(5000):
        e.analyze(syn(f"10.{i // 250}.{i % 250}.9", "93.184.216.34", 80), now=i * 0.001)
    assert len(e._scan) == 5000
    e.analyze(syn(HOST, "93.184.216.34", 443), now=1000.0)
    assert len(e._scan) == 1
    assert len(e._beacon) == 1
    assert len(e._exfil) == 1
