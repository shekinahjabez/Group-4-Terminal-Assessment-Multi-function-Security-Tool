"""
port_scanner_api.py
Provides run_scan() which api.py imports as:
    from web_security_tool.port_scanner_api import run_scan

Wraps your existing MS2 ScanEngine / scan_port logic into a single
function that returns a JSON-serialisable dict.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# ── Common port → service map ─────────────────────────────────────────────────
SERVICE_MAP: dict[int, str] = {
    20: "FTP-Data",   21: "FTP",       22: "SSH",       23: "Telnet",
    25: "SMTP",       53: "DNS",       67: "DHCP",      68: "DHCP",
    69: "TFTP",       80: "HTTP",     110: "POP3",     119: "NNTP",
   123: "NTP",       135: "RPC",      137: "NetBIOS",  138: "NetBIOS",
   139: "NetBIOS",   143: "IMAP",     161: "SNMP",     194: "IRC",
   389: "LDAP",      443: "HTTPS",    445: "SMB",      465: "SMTPS",
   514: "Syslog",    515: "LPD",      587: "SMTP",     636: "LDAPS",
   993: "IMAPS",     995: "POP3S",   1433: "MSSQL",   1521: "Oracle",
  1723: "PPTP",     3306: "MySQL",   3389: "RDP",     5432: "PostgreSQL",
  5900: "VNC",      5985: "WinRM",   6379: "Redis",   8080: "HTTP-Alt",
  8443: "HTTPS-Alt",8888: "HTTP-Dev",27017: "MongoDB",
}

# ── Risk classification ───────────────────────────────────────────────────────
HIGH_RISK   = {21, 23, 135, 137, 138, 139, 445, 1433, 3389, 5900}
MEDIUM_RISK = {22, 25, 53, 80, 110, 143, 389, 443, 3306, 5432, 6379, 27017}

def _risk(port: int) -> str:
    # figures out how risky an open port is based on what service it runs
    if port in HIGH_RISK:   return "high"
    if port in MEDIUM_RISK: return "medium"
    return "low"

# ── Port profiles ─────────────────────────────────────────────────────────────
COMMON_PORTS = sorted(SERVICE_MAP.keys())

# ── Core TCP probe ────────────────────────────────────────────────────────────
def _probe(host: str, port: int, timeout: float) -> dict[str, Any]:
    # tries to connect to a single port and returns open/closed/filtered
    """Return a single port result dict."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            state = "open"
    except ConnectionRefusedError:
        state = "closed"
    except OSError:
        state = "filtered"

    return {
        "port":    port,
        "state":   state,
        "service": SERVICE_MAP.get(port, "unknown"),
        "risk":    _risk(port) if state == "open" else "info",
    }

# ── Port list builder ─────────────────────────────────────────────────────────
def _build_port_list(
    mode: str,
    start: int,
    end: int,
    ports_str: str,
) -> list[int]:
    # builds the list of ports to scan based on the selected mode
    if mode == "common":
        return COMMON_PORTS

    if mode == "range":
        lo, hi = min(start, end), max(start, end)
        return list(range(lo, min(hi, 65535) + 1))

    if mode == "custom":
        result: list[int] = []
        for token in ports_str.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                parts = token.split("-", 1)
                try:
                    a, b = int(parts[0]), int(parts[1])
                    result.extend(range(min(a, b), min(max(a, b), 65535) + 1))
                except ValueError:
                    pass
            else:
                try:
                    p = int(token)
                    if 1 <= p <= 65535:
                        result.append(p)
                except ValueError:
                    pass
        return sorted(set(result))

    return COMMON_PORTS

# ── Public API ────────────────────────────────────────────────────────────────
def run_scan(
    host:    str,
    mode:    str   = "common",
    timeout: float = 0.8,
    start:   int   = 1,
    end:     int   = 1024,
    ports:   str   = "",
) -> dict[str, Any]:
    # scans all the ports in the list and returns the open ones
    """
    Run a TCP port scan and return a JSON-serialisable result dict.

    Parameters mirror the ScanRequest model in api.py:
        host    — hostname or IP address
        mode    — "common" | "range" | "custom"
        timeout — per-port connect timeout in seconds
        start   — range start (used when mode=="range")
        end     — range end   (used when mode=="range")
        ports   — comma/range string (used when mode=="custom")

    Returns:
        {
          host, ip, mode, total_scanned, open_count,
          scan_time,          # float seconds
          ports: [            # only OPEN ports
            { port, state, service, risk }
          ]
        }
    """
    host = host.strip()
    if not host:
        raise ValueError("host must not be empty")

    # Resolve hostname once
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host '{host}': {exc}") from exc

    port_list = _build_port_list(mode, start, end, ports)
    if not port_list:
        raise ValueError("No valid ports to scan.")

    t0      = time.monotonic()
    results = []

    # Parallel scan — cap workers to avoid overwhelming the target
    max_workers = min(100, len(port_list))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe, ip, p, timeout): p for p in port_list}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass

    scan_time  = round(time.monotonic() - t0, 2)
    open_ports = [r for r in results if r["state"] == "open"]
    open_ports.sort(key=lambda r: r["port"])

    return {
        "host":          host,
        "ip":            ip,
        "mode":          mode,
        "total_scanned": len(port_list),
        "open_count":    len(open_ports),
        "scan_time":     scan_time,
        "ports":         open_ports,
    }