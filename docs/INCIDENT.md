# Incident write-up: C2 implant on a hospital bastion host

> Lab exercise from Epitech's defensive-security module (M2). The hospital is a fictional training scenario.
> The IOCs below come from the analysed sample and point to lab infrastructure.

## Context

The bastion host fronting a fictional hospital network (reverse proxy for mail and the patient-records application) was suspected of compromise. The network was monitored by Suricata in IPS mode (NFQUEUE). The goal was to investigate, build detection, and contain the threat.

## 1. Discovery

- An unknown process `/tmp/openssh_server` was running as `www-data`. It was named to blend in with the real SSH daemon.
- The container's **init script** (PID 1, `/var/run/tpdc`) started it **before** Suricata, and only *forwarded* traffic went through NFQUEUE. Traffic leaving the bastion itself therefore **never reached the IDS**, which explains why Suricata showed nothing.

## 2. Malware analysis (static)

| Property | Value |
|---|---|
| Format | ELF64 x86-64 PIE, not stripped, GCC 14.2 (source file `agent.c`) |
| SHA-256 | `47db8dff4de1802323f6926d4ae36a5a270ce27088c565f4123079d64149ac79` |
| Libraries | libcurl (C2 over HTTP), OpenSSL (AES-256-CBC) |

**Capabilities**
- **C2 over plain HTTP** to `goog1e.eu` (a typosquat of google.com), with endpoints `/ping` (heartbeat), `/beacon` (fetch tasks), `/result`, `/upload`, `/agent_version` and `/agent_download` (self-update through `execv`)
- **Tasks**: `exec` runs a shell command (`popen`) and sends back base64 output; `exfil` uploads a file; `encrypt` encrypts a file with AES-256-CBC before upload
- **Persistence on several layers**: a root systemd service, a user systemd service, a `* * * * *` crontab entry and a `~/.bashrc` launcher, plus a single-instance lock in `/tmp/agent.pid`

**IOCs**: `116.202.5.225`, `goog1e.eu`, user-agent `curl/8.5.0`, `/tmp/openssh_server`, `/tmp/agent.pid`, `/tmp/agent_persist_installed`, `agent.service`, env vars `AGENT_RUNNING` and `AGENT_ID`.

## 3. Detection

Because the IDS was blind to host-originated traffic, I built this SIEM to sniff the bastion's own interface. The rules come straight from the analysis:

| Malware behaviour | Rule |
|---|---|
| Talks to `116.202.5.225` / resolves `goog1e.eu` | R01 `C2_DIRECT_HIT` |
| Heartbeat at a fixed interval | R02 `C2_BEACON` |
| File uploads | R03 `C2_EXFIL_VOLUME` |
| `POST /beacon`, `/upload`, `/result` with a `curl/` user-agent | R09 `HTTP_C2_PATTERN` |

Generic rules (reverse-shell ports, DGA / DNS tunnelling, port scans, ICMP tunnels) cover follow-up activity and variants.

## 4. Containment and eradication

1. Blocked the C2 in both directions with iptables and sinkholed `goog1e.eu` in `/etc/hosts`. Verified that the C2 became unreachable.
2. Killed the implant process.
3. Removed the binary, lock and marker files, and the systemd unit. Checked the crontabs.
4. Ran the SIEM in `--block` mode to contain any re-infection automatically.

## 5. Recommendations

- Send **host-originated** traffic through the IPS too (`OUTPUT` chain → NFQUEUE), not only forwarded traffic
- Restrict egress from the bastion to an allow-list. A reverse proxy has no reason to reach arbitrary hosts on port 80.
- Run file-integrity monitoring on init scripts, systemd units, crontabs and shell rc files
- Mount `/tmp` with `noexec`
