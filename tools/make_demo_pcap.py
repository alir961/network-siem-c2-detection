"""
Generate a synthetic capture reproducing the incident traffic, to demo the SIEM without root.

    python tools/make_demo_pcap.py demo/incident.pcap
"""
import sys

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

HOST = "192.168.5.100"     # compromised bastion
RESOLVER = "192.168.5.1"
C2 = "116.202.5.225"       # goog1e.eu
T0 = 1_772_683_200.0       # fixed start time so the output is reproducible


def at(pkt, t):
    pkt.time = T0 + t
    return pkt


def beacon(t, sport):
    req = HTTP() / HTTPRequest(Method=b"POST", Path=b"/beacon", Host=b"goog1e.eu", User_Agent=b"curl/8.5.0")
    return [
        at(IP(src=HOST, dst=C2) / TCP(sport=sport, dport=80, flags="S"), t),
        at(IP(src=HOST, dst=C2) / TCP(sport=sport, dport=80, flags="PA") / req, t + 0.05),
    ]


pkts = [at(IP(src=HOST, dst=RESOLVER) / UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname="goog1e.eu")), 0)]
# 1. The implant beacons to its C2 every 120 s
for i in range(5):
    pkts += beacon(1 + 120 * i, 41000 + i)
# 2. Exfiltration: a large upload to /upload
up = HTTP() / HTTPRequest(Method=b"POST", Path=b"/upload", Host=b"goog1e.eu", User_Agent=b"curl/8.5.0")
pkts.append(at(IP(src=HOST, dst=C2) / TCP(sport=42000, dport=80, flags="S"), 300))
pkts.append(at(IP(src=HOST, dst=C2) / TCP(sport=42000, dport=80, flags="PA") / up, 300.1))
pkts += [at(IP(src=HOST, dst=C2) / TCP(sport=42000, dport=80, flags="PA") / Raw(b"\x00" * 1400), 300.2 + i * 0.01)
         for i in range(150)]
# 3. DGA-looking lookups and a reverse-shell attempt
pkts.append(at(IP(src=HOST, dst=RESOLVER) / UDP(sport=40001, dport=53)
               / DNS(rd=1, qd=DNSQR(qname="xk7qp9m3bvzw1.top")), 310))
pkts.append(at(IP(src=HOST, dst="203.0.113.66") / TCP(sport=43000, dport=4444, flags="S"), 320))
# 4. An external host scans the bastion
pkts += [at(IP(src="198.51.100.23", dst=HOST) / TCP(sport=50000, dport=p, flags="S"), 400 + p * 0.001)
         for p in range(20, 60)]
# 5. ICMP tunnel
pkts.append(at(IP(src=HOST, dst="203.0.113.99") / ICMP(type=8) / Raw(b"A" * 512), 500))
# Normal traffic that must NOT alert
pkts += [at(IP(src=HOST, dst=f"93.184.216.{i}") / TCP(sport=44000 + i, dport=443, flags="S"), 600 + i)
         for i in range(30)]
pkts.append(at(IP(src=HOST, dst=RESOLVER) / UDP(sport=40002, dport=53) / DNS(rd=1, qd=DNSQR(qname="debian.org")), 700))

wrpcap(sys.argv[1] if len(sys.argv) > 1 else "demo/incident.pcap", sorted(pkts, key=lambda p: p.time))
