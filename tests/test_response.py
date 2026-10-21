"""
Tests for active response, alert dedup, logging and pcap replay.
"""
import json

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from siem.alert import AlertDispatcher
from siem.capture import SIEMCapture
from siem.config import system_resolvers
from siem.firewall import Firewall
from siem.logger import SIEMLogger
from siem.main import main
from siem.rules import DetectionEngine


def alert(offender, severity="HIGH"):
    return {"rule": "X", "severity": severity, "src": "a", "dst": "b", "offender": offender, "details": {}}


def test_never_blocks_internal_or_missing_offender():
    fw = Firewall(dry_run=True)
    assert fw.should_block(alert("192.168.5.1")) is None  # gateway / resolver
    assert fw.should_block(alert(None)) is None
    assert fw.should_block(alert("not-an-ip")) is None


def test_blocks_external_once_and_only_on_high():
    fw = Firewall(dry_run=True)
    assert fw.should_block(alert("1.2.3.4", "MEDIUM")) is None
    assert fw.should_block(alert("1.2.3.4")) == "1.2.3.4"
    fw.block("1.2.3.4")
    assert fw.should_block(alert("1.2.3.4")) is None


def pipeline(tmp_path, firewall=None):
    return SIEMCapture(DetectionEngine(), AlertDispatcher(), SIEMLogger(str(tmp_path / "a.jsonl")),
                       firewall=firewall, verbose=False)


def test_duplicate_alerts_are_suppressed(tmp_path):
    p = pipeline(tmp_path)
    pkt = IP(src="192.168.5.3", dst="1.2.3.4") / TCP(dport=4444, flags="S")
    for t in (0, 10, 20, 100):
        p.process(pkt, now=float(t))
    assert p.stats["alerts"] == 2  # t=0 and t=100 (dedup window is 60 s)
    assert p.stats["suppressed"] == 2


def test_replay_logs_packet_time_and_blocks(tmp_path, capsys):
    pkt = IP(src="192.168.5.3", dst="116.202.5.225") / TCP(dport=80, flags="S")
    pkt.time = 1_772_683_200  # 2026-03-05T04:00:00Z
    pcap = tmp_path / "c.pcap"
    wrpcap(str(pcap), [pkt])
    log = tmp_path / "alerts.jsonl"

    assert main(["--pcap", str(pcap), "--log", str(log), "--block", "--dry-run"]) == 0

    entries = [json.loads(line) for line in log.read_text().splitlines()]
    assert entries[0]["rule"] == "C2_DIRECT_HIT"
    assert entries[0]["timestamp"] == "2026-03-05T04:00:00Z"
    assert "Blocked: 116.202.5.225" in capsys.readouterr().out


def test_never_blocks_protected_addresses_even_from_a_forged_scan():
    fw = Firewall(dry_run=True, never_block={"1.1.1.1"})
    assert fw.should_block(alert("1.1.1.1", "CRITICAL")) is None
    assert fw.should_block(alert("1.2.3.4")) == "1.2.3.4"


def test_resolvers_are_read_from_resolv_conf(tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("# generated\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\nsearch lan\n")
    assert system_resolvers(str(conf)) == {"1.1.1.1", "2606:4700:4700::1111"}
    assert system_resolvers(str(tmp_path / "missing")) == set()
