# CUPS / `cups-browsed` Discovery Attack & Detection (CVE-2024-47176)

DAT505 Assignment 2 — Marius Langeland

Scapy-based tools that demonstrate and detect insecure CUPS printer discovery
(the CVE-2024-47176 class), plus a mitigation experiment. All work is performed
in an isolated Docker lab.

## Repository layout

| Path | Description |
|------|-------------|
| `cups_attack.py` | Scapy attack tool — advertises an attacker-controlled printer and observes the victim's callback. |
| `cups_detector.py` | Scapy detection tool — flags unauthorized adverts, suspicious IPP callbacks, malformed fields, and floods. |
| `requirements.txt` | Python dependencies. |
| `pcap_files/` | Captured network traffic (one capture per experiment). |
| `evidence/` | Detector logs, screenshots |

The vulnerable environment itself is **not** committed. Clone
it separately (below).

## Requirements

- Python 3.10+
- [Scapy](https://scapy.net/) — `pip install -r requirements.txt`
- `root` / `sudo` (raw sockets for sniffing and sending)
- `tcpdump` (packet capture), `docker` + `docker compose` (victim container)

```bash
sudo apt install -y tcpdump
pip install -r requirements.txt
```

## Lab setup

```bash
# 1. Clone the vulnerable environment (kept out of this repo)
git clone https://github.com/vulhub/vulhub
cd vulhub/cups-browsed/CVE-2024-47177
sudo docker compose up -d        # victim 'cups-browsed' container

# 2. Start a software printer on the host (no physical printer needed)
ippeveprinter -p 8632 "Test Printer"
```

Typical lab addresses: victim `172.18.0.2`, attacker/host `172.18.0.1`
(the Docker bridge gateway), bridge interface `br-<id>`. Derive them with:

```bash
VICTIM=$(sudo docker ps -q | head -1)
sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$VICTIM"
```

## Usage

### Detector

```bash
sudo python3 cups_detector.py --iface <iface> \
    [--known-printers known_printers.csv] \
    [--window 10] [--threshold 5] \
    [--filter "udp port 631 or tcp"] [-v]
```

- `--known-printers` — CSV allowlist, format `ip,name,port`. Advertisers not in
  the list are flagged `[UNAUTHORIZED AD]`.
- `--window` / `--threshold` — flood detection (default: more than 5
  announcements from one source within 10 s raises `[FLOOD]`).
- Alerts: `[UNAUTHORIZED AD]`, `[SUSPICIOUS IPP]`, `[MALFORMED]`, `[FLOOD]`.

### Attack

```bash
sudo python3 cups_attack.py --adv-ip <callback-ip> [--target <victim-ip>] \
    [-h] [--target TARGET] [--target-port TARGET_PORT] \
    [--adv-port ADV_PORT] [--queue QUEUE] [-v] [--iface IFACE] \
    [--pcap PCAP] [--listen-timeout LISTEN_TIMEOUT] [--state STATE] \
    [--printer-type PRINTER_TYPE] [--no-listen]
```

| Flag | Description |
|------|-------------|
| `--adv-ip <callback-ip>` | Address advertised as the printer, i.e. where the victim connects back. |
| `--target <victim-ip>` | The victim's `cups-browsed` host; the UDP 631 announcement is sent here. |
| `--target-port <port>` | UDP port on the victim that `cups-browsed` listens on (default 631). |
| `--adv-port <port>` | Port placed in the advertised printer URI — the port the victim connects back to on `--adv-ip` (e.g. `631` normal, `9999` crafted). |
| `--queue <name>` | Printer/queue name embedded in the advertised URI (e.g. `LabPrinter`, `evilprinter`, `flood1`). |
| `--state <value>` | `printer-state` field in the browse packet; normal is 3/4/5, a crafted value such as `99` tests the detector. |
| `--printer-type <value>` | `type` field (normally hex, e.g. `0x1000002`); a non-hex value such as `zzz` tests validation. |
| `--iface <iface>` | Network interface used to send the announcement and observe the callback. |
| `--pcap <file>` | Write captured packets to this pcap file. |
| `--listen-timeout <seconds>` | How long to wait for the victim's callback before giving up (the `No callback within Ns` message). |
| `--no-listen` | Don't open the callback listener / don't wait for the victim to connect back (fire-and-forget, as in the flood loop). |
| `-v`, `--verbose` | Verbose logging. |
| `-h`, `--help` | Show the usage message and exit. |

## Experiments

1. **Normal traffic** — a well-formed, allowlisted advert on port 631 -> no alerts.
2. **Unauthorized discovery** — advert from an unknown source: `[UNAUTHORIZED AD]`
   + `[SUSPICIOUS IPP]` on the callback.
3. **Packet manipulation** — four crafted variants: abnormal `printer-state`,
   invalid `type`, non-standard `port`, and a flood of 8 announcements.
4. **Detection evaluation** — true positives, false positives (e.g. a legitimate
   printer on a non-standard port), and missed attacks (allowlisted/spoofed
   source, or the mDNS/DNS-SD path the filter does not watch).

## Mitigation

Restricting UDP 631 at the victim's firewall stops `cups-browsed` acting on the
advert (the coerced callback no longer occurs):

```bash
PID=$(sudo docker inspect -f '{{.State.Pid}}' "$VICTIM")
sudo nsenter -t "$PID" -n iptables -I INPUT -p udp --dport 631 -j DROP
```

Other layers: disable `cups-browsed` / `BrowseRemoteProtocols none`, allowlist
authorized printers, patch to `cups-browsed` 2.1.0, and segment the network.

## Ethics & safety

All testing was confined to a self-controlled, isolated Docker lab. No external
systems were targeted. The vulnerability and its mitigations are public
(CVE-2024-47176); the purpose of this work is defensive understanding and
detection.
