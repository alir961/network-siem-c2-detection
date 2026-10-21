# Network SIEM — C2, Exfiltration & Reconnaissance Detection

![CI](https://github.com/alir961/network-siem-c2-detection/actions/workflows/ci.yml/badge.svg)

A lightweight, packet-level SIEM written in Python and Scapy. It detects **command-and-control beaconing, data exfiltration, DNS abuse, scans and tunnels**, alerts in real time (Discord / Telegram / JSON Lines), and can **contain threats automatically** with iptables.

> **School project** (Epitech, M2 defensive-security module): an incident-response exercise on a simulated hospital network.

In the exercise, a bastion host had been compromised and its IDS was blind to the implant's traffic. I reverse-engineered the malware sample and turned its behaviour into the detection rules below. Read the full investigation: **[docs/INCIDENT.md](docs/INCIDENT.md)**.

## Supported platforms

| OS | Pcap replay and tests | Live capture | `--block` (iptables) |
|---|---|---|---|
| Linux | Yes (CI: Ubuntu, Python 3.10 and 3.12) | Yes | Yes |
| macOS | Yes | Not tested | No (no iptables) |
| Windows | Yes (use `.venv\Scripts\activate`) | Not tested (Scapy needs [Npcap](https://npcap.com)) | No (no iptables) |

Use Linux for live detection and active response. On Windows, WSL 2 runs the replay and the tests, but it only sees its own virtual network interface.

## Requirements

- **Python 3.10+** with `venv` and `pip` (tested on 3.10, 3.12 and 3.14)
- Dependencies, installed by pip: Scapy ≥ 2.5 and requests
- Pcap replay (the demo) needs nothing else: no root, no network
- **Live capture**: Linux, root or the `CAP_NET_RAW` capability, and **libpcap** (`tcpdump` package) for `--filter` BPF expressions
- **`--block`** without `--dry-run`: **iptables** and root

## Install

```bash
git clone https://github.com/alir961/network-siem-c2-detection.git
cd network-siem-c2-detection
python3 -m venv .venv
source .venv/bin/activate
pip install -e .            # also installs a `siem` command, same as `python -m siem`
```

A virtual environment is needed on distributions that protect the system Python (Debian 12+, Ubuntu 23.04+, Arch, Fedora): a plain `pip install` there fails with `externally-managed-environment`.

## Demo

Replay the bundled capture. It's synthetic traffic modelled on the exercise, so you don't need root or a live network:

```bash
python -m siem --pcap demo/incident.pcap --block --dry-run
```

```text
[2026-03-05T04:00:00Z] [CRITICAL] C2_DIRECT_HIT          192.168.5.100 -> 192.168.5.1     c2_domain=goog1e.eu proto=DNS
[2026-03-05T04:00:01Z] [CRITICAL] C2_DIRECT_HIT          192.168.5.100 -> 116.202.5.225   c2_ip=116.202.5.225 port=80 proto=TCP direction=outbound
                        [BLOCK] iptables DROP in/out 116.202.5.225 (dry run)
[2026-03-05T04:05:01Z] [CRITICAL] C2_EXFIL_VOLUME        192.168.5.100 -> 116.202.5.225   bytes=200595 window_sec=300
[2026-03-05T04:05:10Z] [CRITICAL] DNS_DGA_SUSPECT        192.168.5.100 -> 192.168.5.1     domain=xk7qp9m3bvzw1.top entropy=3.7
[2026-03-05T04:06:40Z] [HIGH    ] PORT_SCAN              198.51.100.23 -> 192.168.5.100   unique_ports=21 window_sec=0.0
                        [BLOCK] iptables DROP in/out 198.51.100.23 (dry run)
[2026-03-05T04:08:01Z] [HIGH    ] C2_BEACON              192.168.5.100 -> 116.202.5.225   interval_sec=120.0 regular_intervals=3 connections=6
...
[SIEM] 237 packets, 18 alerts (157 duplicates suppressed)
```

Full output: [docs/demo-output.txt](docs/demo-output.txt). The capture also contains 30 ordinary HTTPS connections and a normal DNS lookup, and **none of them raise an alert**.

## Detection rules

| ID | Rule | Detects | Severity |
|---|---|---|---|
| R01 | `C2_DIRECT_HIT` | Traffic to a known C2 IP, or a lookup of a C2 domain | CRITICAL |
| R02 | `C2_BEACON` | Connections to one host at a regular interval. Tolerates unrelated connections in between. | HIGH |
| R03 | `C2_EXFIL_VOLUME` | More than 200 KB sent to one external host within a sliding 5-minute window | CRITICAL |
| R04 | `C2_SUSPICIOUS_PORT` | Outbound connection to common reverse-shell ports (4444, 1337, 31337…) | HIGH |
| R05 | `DNS_HIGH_RATE` | Abnormal DNS query rate (DGA, DNS tunnelling) | HIGH |
| R06 | `DNS_DGA_SUSPECT` | High Shannon entropy in a domain label | CRITICAL |
| R07 | `PORT_SCAN` | One source probing more than 20 ports on one host within 30 s (counts SYNs, so normal browsing doesn't trigger it) | HIGH |
| R08 | `ICMP_DATA_TUNNEL` | ICMP echo carrying an oversized payload | HIGH |
| R09 | `HTTP_C2_PATTERN` | HTTP request to a C2 host or endpoint, or a scripted user-agent (`curl/`, `Wget/`) | CRITICAL / MEDIUM |

## Architecture

```
 live interface ──┐
 (Scapy sniff)    ├──► DetectionEngine ──► dedup (60 s) ──┬──► JSON Lines log
 pcap replay   ───┘     9 stateful rules                  ├──► Discord / Telegram
 (packet time)          + IOC matching                    └──► Firewall (iptables)
```

- **Stateful detection** with sliding windows. The engine takes the clock as a parameter, so live capture and pcap replay share the same logic and tests are deterministic.
- **Guarded active response**: only the alert's *offender* (the external party) is blocked. Internal addresses, the DNS resolvers listed in `/etc/resolv.conf` and the addresses in `SIEM_NEVER_BLOCK` are never blocked. This matters because the source of a scan can be forged: a spoofed scan "from" a public resolver would otherwise cut the host's DNS. Any other external address can still be blocked through a forged scan, so list the services you depend on in `SIEM_NEVER_BLOCK`. Rules are idempotent (`iptables -C` runs before each insert), and `--dry-run` is available.
- **Bounded memory**: per-host state is dropped once its window expires, so a flood of forged sources cannot grow it without limit.
- **Secrets are never committed**: alert channels are configured through environment variables.

## Usage

```bash
# Live capture: run the venv's Python as root (sudo does not keep the activated venv)
ip -br link                                   # find your interface name (eth0, enp3s0, wlan0...)
sudo -E .venv/bin/python -m siem -i eth0 --block --filter "not port 22"

# Offline analysis of a capture (.pcap or .pcapng)
python -m siem --pcap suspicious.pcap

# Custom IOCs
python -m siem --pcap suspicious.pcap --iocs iocs.example.json
```

Stop a live capture with Ctrl+C; the SIEM prints a summary and the addresses it blocked. Rules added by `--block` stay in iptables: list them with `sudo iptables -S | grep DROP` and remove one with `sudo iptables -D INPUT -s <ip> -j DROP` and `sudo iptables -D OUTPUT -d <ip> -j DROP`.

| Option | Purpose |
|---|---|
| `-i`, `--interface` | interface to sniff (default `eth0`, or `SIEM_INTERFACE`) |
| `--pcap FILE` | replay a capture file instead of sniffing live |
| `--filter BPF` | BPF filter for live capture, e.g. `"not port 22"` |
| `--iocs FILE` | JSON file with `c2_ips`, `c2_domains`, `c2_endpoints` (see [`iocs.example.json`](iocs.example.json)) |
| `--block` | block HIGH and CRITICAL offenders with iptables |
| `--dry-run` | with `--block`: report the blocks without touching iptables |
| `--log FILE` | JSON Lines alert log (default `/tmp/siem_logs/alerts.jsonl`) |
| `-q`, `--quiet` | only print CRITICAL alerts |

`python -m siem --help` lists the options and the rules.

Alert channels are optional and read from the environment:

| Variable | Purpose |
|---|---|
| `SIEM_DISCORD_WEBHOOK` | Discord webhook URL for alerts |
| `SIEM_TELEGRAM_TOKEN`, `SIEM_TELEGRAM_CHAT_ID` | Telegram bot alerts |
| `SIEM_INTERFACE`, `SIEM_LOG_DIR` | Defaults for the interface and log directory |
| `SIEM_NEVER_BLOCK` | Comma-separated addresses `--block` must never block (DNS resolvers are already included) |

Detection thresholds are in [`siem/config.py`](siem/config.py).

## Development

```bash
pip install -e ".[dev]"   # in the venv: adds pytest and Ruff
pytest          # 26 tests: every rule, plus false-positive cases, response safety and replay
ruff check .
python tools/make_demo_pcap.py demo/incident.pcap   # regenerate the demo capture
```

CI runs lint, the test suite and a demo replay on Python 3.10 and 3.12.

## Tech stack

Python · Scapy · iptables · Discord & Telegram APIs · pytest · Ruff · GitHub Actions
