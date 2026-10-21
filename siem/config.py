"""
SIEM configuration.

Network-specific values (interface, subnets, IOCs) live here. Secrets for
alert channels are read from the environment and never stored in this file.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

INTERFACE = os.environ.get("SIEM_INTERFACE", "eth0")

INTERNAL_SUBNETS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.0/8",
]

WHITELIST_IPS: set[str] = set()


def system_resolvers(path: str = "/etc/resolv.conf") -> set[str]:
    """Nameservers the host uses; blocking one would break its DNS."""
    resolvers: set[str] = set()
    try:
        for line in Path(path).read_text().splitlines():
            words = line.split()
            if len(words) >= 2 and words[0] == "nameserver":
                resolvers.add(words[1])
    except OSError:
        pass
    return resolvers


# Addresses active response never blocks, even when they are an alert's offender.
# The source address of a scan or an inbound packet can be forged, so without this
# a spoofed scan "from" the public DNS resolver would cut the host's DNS.
# Add more with SIEM_NEVER_BLOCK="1.2.3.4,5.6.7.8".
NEVER_BLOCK_IPS: set[str] = system_resolvers() | {
    ip.strip() for ip in os.environ.get("SIEM_NEVER_BLOCK", "").split(",") if ip.strip()
}

THRESHOLDS = {
    "beaconing_window_sec":   600,
    "beaconing_min_count":    4,
    "beaconing_jitter_ratio": 0.1,
    "beaconing_min_interval": 5.0,
    "exfil_bytes_threshold":  200_000,
    "exfil_window_sec":       300,
    "dns_rate_window_sec":    60,
    "dns_rate_threshold":     30,
    "dga_entropy_threshold":  3.5,
    "dga_min_label_length":   8,
    "port_scan_threshold":    20,
    "port_scan_window_sec":   30,
    "icmp_payload_threshold": 64,
    "suspicious_ports": {
        4444, 4445, 1337, 31337, 8080, 8443, 9001, 6666, 1234, 5555,
        2222, 3333, 7777, 9999, 12345, 54321,
    },
    "alert_dedup_window_sec": 60,
}

# Alert channels: set these in the environment, never commit them.
DISCORD_WEBHOOK_URL = os.environ.get("SIEM_DISCORD_WEBHOOK", "")
TELEGRAM_BOT_TOKEN  = os.environ.get("SIEM_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID    = os.environ.get("SIEM_TELEGRAM_CHAT_ID", "")

LOG_DIR  = os.environ.get("SIEM_LOG_DIR", "/tmp/siem_logs")
LOG_FILE = f"{LOG_DIR}/alerts.jsonl"


@dataclass
class IOCs:
    """Indicators of compromise the engine matches against."""
    c2_ips: set[str] = field(default_factory=set)
    c2_domains: set[str] = field(default_factory=set)
    c2_endpoints: list[str] = field(default_factory=list)
    malware_sha256: set[str] = field(default_factory=set)

    @classmethod
    def from_file(cls, path: str | Path) -> IOCs:
        data = json.loads(Path(path).read_text())
        return cls(
            c2_ips=set(data.get("c2_ips", [])),
            c2_domains=set(data.get("c2_domains", [])),
            c2_endpoints=list(data.get("c2_endpoints", [])),
            malware_sha256=set(data.get("malware_sha256", [])),
        )


# IOCs extracted from the malware analysed during the incident (see docs/INCIDENT.md)
DEFAULT_IOCS = IOCs(
    c2_ips={"116.202.5.225"},
    c2_domains={"goog1e.eu"},
    c2_endpoints=["/ping", "/beacon", "/upload", "/result", "/agent_version", "/agent_download"],
    malware_sha256={"47db8dff4de1802323f6926d4ae36a5a270ce27088c565f4123079d64149ac79"},
)
