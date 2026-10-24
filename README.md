# Python TCP/UDP Port Scanner

A lightweight, multithreaded TCP and UDP port scanner written in pure Python (standard library only, no dependencies).

Built for **Ethical Hacking 7A, Assignment 1** at Superior University, Lahore.

## Features

- TCP connect scan (full 3-way handshake)
- UDP scan with protocol-specific probes (DNS, NTP, SNMP, SSDP)
- Multithreaded for fast scanning
- Flexible port selection: single, list, or range
- Service name lookup
- Optional TCP banner grabbing
- Save terminal output to a text file and/or structured results to JSON
- Zero dependencies, runs on Python 3.7+

## Usage

```bash
python3 portscanner.py <target> [options]
```

| Option | Description |
|---|---|
| `-p, --ports` | Ports to scan, e.g. `80`, `22,80,443`, `1-1024` (default: `1-1024`) |
| `-t, --threads` | Number of worker threads (default: 200) |
| `--timeout` | Per-port timeout in seconds (default: 1.0) |
| `--tcp-only` | Scan TCP only |
| `--udp-only` | Scan UDP only |
| `--banner` | Grab service banners from open TCP ports |
| `--json FILE` | Save structured results to a JSON file |
| `-o, --output FILE` | Save terminal output to a text file |

### Examples

```bash
# Default scan (TCP + UDP, ports 1-1024)
python3 portscanner.py scanme.nmap.org

# Full TCP scan with more threads
python3 portscanner.py scanme.nmap.org -p 1-65535 --tcp-only -t 300

# Specific ports with banner grabbing and JSON export
python3 portscanner.py scanme.nmap.org -p 22,80,443 --banner --json scan.json

# Save terminal output for a report
python3 portscanner.py scanme.nmap.org -o result.txt
```

### Sample output

```
TCP scan results:
PORT        STATE           SERVICE       BANNER
----------------------------------------
22/tcp      open            ssh           SSH-2.0-OpenSSH_8.9
80/tcp      open            http          HTTP/1.1 200 OK

Summary (TCP): 1022 closed, 2 open
```

## How it works

**TCP:** the scanner calls `connect()` on each port.
- Handshake completes: `open`
- Connection refused (RST): `closed`
- No response / timeout: `filtered` (likely a firewall)

**UDP:** UDP has no handshake, so results are inferred.
- A UDP reply: `open`
- ICMP "port unreachable": `closed`
- No reply after retries: `open|filtered`

Because UDP services often ignore malformed or empty packets, the scanner sends valid protocol-specific probes for common services. Even so, `open|filtered` is a normal and expected result for many UDP ports. Nmap behaves the same way.

## Limitations

- Connect scans are noisier and easier to detect than SYN (half-open) scans, but need no root privileges.
- UDP scanning is slow and less definitive, especially when firewalls drop ICMP errors or the network blocks outbound UDP.
- IPv4 only.
- Service names come from the local services database, not from fingerprinting.

## Legal & ethical use

**Only scan systems you own or have explicit written permission to test.** Unauthorized port scanning may be illegal in your jurisdiction and violate terms of service. This tool was written for educational use, and the author accepts no responsibility for misuse.

## Author

Muhammad Umer Saqib, BS Cyber Security, Superior University, Lahore
