"""
SIEM Configuration — G-SEC-910 Hôpital Mandé
"""

INTERFACE = "eth0"

INTERNAL_SUBNETS = [
    "192.168.5.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.0/8",
]

WHITELIST_IPS: set[str] = set()
WHITELIST_PORTS: set[int] = {22, 53, 80, 443, 123}

# IOCs confirmed by Phase 2 malware analysis
C2_IPS: set[str] = {"116.202.5.225"}
C2_DOMAINS: set[str] = {"goog1e.eu"}
C2_PORTS: set[int] = {80}
C2_USER_AGENT_FRAGMENT = "curl/"
C2_ENDPOINTS: list[str] = [
    "/ping", "/beacon", "/upload", "/result",
    "/agent_version", "/agent_download",
]

MALWARE_SHA256 = "47db8dff4de1802323f6926d4ae36a5a270ce27088c565f4123079d64149ac79"

THRESHOLDS = {
    "beaconing_window_sec":   120,
    "beaconing_min_count":    4,
    "beaconing_variance_max": 10.0,
    "beaconing_min_interval": 5.0,
    "exfil_bytes_threshold":  200_000,
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

DISCORD_WEBHOOK_URL = ""
TELEGRAM_BOT_TOKEN  = ""
TELEGRAM_CHAT_ID    = ""

LOG_DIR  = "/tmp/siem_logs"
LOG_FILE = f"{LOG_DIR}/alerts.jsonl"
