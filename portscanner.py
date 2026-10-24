#!/usr/bin/env python3
"""
portscanner.py - Simple multithreaded TCP + UDP port scanner
Ethical Hacking 7A - Assignment 1 (Superior University)

Usage examples:
    python3 portscanner.py stream.aiprotocol.info
    python3 portscanner.py stream.aiprotocol.info -p 1-1024
    python3 portscanner.py stream.aiprotocol.info -p 1-65535 --tcp-only -t 300
    python3 portscanner.py stream.aiprotocol.info --udp-only -p 1-1024 -o result.txt
    python3 portscanner.py stream.aiprotocol.info -p 1-1024 --banner --json scan.json

How it works:
  TCP: full connect() scan. If the 3-way handshake completes -> open.
       Refused -> closed. No reply / timeout -> filtered.
  UDP: send a probe datagram.
       Any UDP reply            -> open
       ICMP port unreachable    -> closed (shows up as ConnectionRefusedError)
       No reply / timeout       -> open|filtered (UDP can't tell these apart)

Only scan systems you own or have explicit permission to test.
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Protocol-specific UDP probes so services actually answer (empty packets are
# usually ignored, which would make everything look "open|filtered").
UDP_PROBES = {
    53: bytes.fromhex(  # DNS query for "version.bind"-style A lookup of example.com
        "aaaa01000001000000000000076578616d706c6503636f6d0000010001"
    ),
    123: b"\x1b" + 47 * b"\x00",  # NTP client request
    161: bytes.fromhex(  # SNMPv1 get-request, community "public"
        "302602010004067075626c6963a019020400000001020100020100300b300906052b060102010500"
    ),
    1900: (  # SSDP M-SEARCH
        b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
        b"MAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n"
    ),
}
DEFAULT_UDP_PROBE = b"\x00"


def service_name(port, proto):
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def parse_ports(spec):
    """Accepts '80', '1-1024', '22,80,443', or combinations like '1-100,443'."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Invalid port: {part}")
            ports.add(p)
    return sorted(ports)


def grab_banner(ip, port, timeout):
    """Try to read a service banner from an open TCP port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8000, 8080, 8081, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                data = s.recv(256)
            except socket.timeout:
                return ""
            text = data.decode("utf-8", errors="replace").strip()
            return text.splitlines()[0][:80] if text else ""
    except OSError:
        return ""


def scan_tcp(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            return port, "open"
        if result in (111, 10061):  # ECONNREFUSED (Linux / Windows)
            return port, "closed"
        return port, "filtered"
    except socket.timeout:
        return port, "filtered"
    except OSError:
        return port, "filtered"
    finally:
        s.close()


def scan_udp(ip, port, timeout, retries=2):
    probe = UDP_PROBES.get(port, DEFAULT_UDP_PROBE)
    for _ in range(retries):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))  # connected UDP lets us see ICMP errors
            s.send(probe)
            s.recv(1024)
            return port, "open"
        except ConnectionRefusedError:
            return port, "closed"  # ICMP port unreachable received
        except socket.timeout:
            continue  # retry, then fall through to open|filtered
        except OSError:
            continue
        finally:
            s.close()
    return port, "open|filtered"


def run_scan(label, func, ip, ports, timeout, threads):
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(func, ip, p, timeout) for p in ports]
        for f in as_completed(futures):
            port, state = f.result()
            results[port] = state
    return results


def format_report(proto, results, banners=None):
    banners = banners or {}
    shown = {p: s for p, s in results.items() if s in ("open", "open|filtered")}
    counts = {}
    for s in results.values():
        counts[s] = counts.get(s, 0) + 1

    lines = []
    lines.append(f"\n{proto.upper()} scan results:")
    lines.append(f"{'PORT':<12}{'STATE':<16}{'SERVICE':<14}BANNER" if banners else f"{'PORT':<12}{'STATE':<16}SERVICE")
    lines.append("-" * 40)
    # For UDP, open|filtered is usually huge; only list definite opens unless few.
    if proto == "udp":
        listed = {p: s for p, s in results.items() if s == "open"}
        if not listed and counts.get("open|filtered", 0) <= 20:
            listed = shown
    else:
        listed = {p: s for p, s in results.items() if s == "open"}

    if listed:
        for port in sorted(listed):
            svc = service_name(port, proto)
            if banners:
                lines.append(f"{str(port) + '/' + proto:<12}{listed[port]:<16}{svc:<14}{banners.get(port, '')}")
            else:
                lines.append(f"{str(port) + '/' + proto:<12}{listed[port]:<16}{svc}")
    else:
        lines.append("(no open ports found)")

    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
    lines.append(f"\nSummary ({proto.upper()}): {summary}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Simple TCP/UDP port scanner")
    ap.add_argument("target", help="Hostname or IPv4 address")
    ap.add_argument("-p", "--ports", default="1-1024", help="Ports, e.g. 1-1024 or 22,80,443 (default 1-1024)")
    ap.add_argument("-t", "--threads", type=int, default=200, help="Worker threads (default 200)")
    ap.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout in seconds (default 1.0)")
    ap.add_argument("--tcp-only", action="store_true", help="Scan TCP only")
    ap.add_argument("--udp-only", action="store_true", help="Scan UDP only")
    ap.add_argument("--banner", action="store_true", help="Grab service banners from open TCP ports")
    ap.add_argument("--json", metavar="FILE", help="Save structured results to a JSON file")
    ap.add_argument("-o", "--output", help="Also save the terminal output to this file")
    args = ap.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"[!] {e}")

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"[!] Could not resolve {args.target}")

    out = []

    def emit(text=""):
        print(text)
        out.append(text)

    start = time.time()
    emit("=" * 50)
    emit(" Python TCP/UDP Port Scanner - Ethical Hacking 7A")
    emit("=" * 50)
    emit(f"Target     : {args.target} ({ip})")
    emit(f"Ports      : {args.ports} ({len(ports)} ports)")
    emit(f"Threads    : {args.threads}   Timeout: {args.timeout}s")
    emit(f"Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    report = {"target": args.target, "ip": ip, "started": datetime.now().isoformat(timespec="seconds"), "tcp": {}, "udp": {}}
    try:
        if not args.udp_only:
            emit("\n[*] Running TCP scan...")
            tcp = run_scan("tcp", scan_tcp, ip, ports, args.timeout, args.threads)
            banners = {}
            if args.banner:
                for p in sorted(p for p, st in tcp.items() if st == "open"):
                    banners[p] = grab_banner(ip, p, args.timeout)
            emit(format_report("tcp", tcp, banners))
            report["tcp"] = {str(p): {"state": st, "service": service_name(p, "tcp"), "banner": banners.get(p, "")}
                             for p, st in tcp.items() if st == "open"}
        if not args.tcp_only:
            emit("\n[*] Running UDP scan (slower: waits for timeouts)...")
            udp = run_scan("udp", scan_udp, ip, ports, args.timeout, min(args.threads, 100))
            emit(format_report("udp", udp))
            report["udp"] = {str(p): {"state": st, "service": service_name(p, "udp")}
                             for p, st in udp.items() if st == "open"}
    except KeyboardInterrupt:
        emit("\n[!] Scan interrupted by user")

    emit(f"\nScan finished in {time.time() - start:.2f} seconds")

    if args.json:
        report["duration_seconds"] = round(time.time() - start, 2)
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON saved to {args.json}")

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(out) + "\n")
        print(f"[+] Output saved to {args.output}")


if __name__ == "__main__":
    main()
