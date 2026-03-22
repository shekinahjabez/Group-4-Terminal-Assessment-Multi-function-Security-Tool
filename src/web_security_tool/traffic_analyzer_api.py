"""
traffic_analyzer_api.py  (fixed)
- Yields first batch immediately (no delay before first data)
- Sends SSE keepalive comments to prevent premature connection close
- Falls back cleanly to simulation on Windows / non-root
- stream_traffic is an async generator (asyncio.sleep) — non-blocking under concurrent load (BUG-03)
"""

import asyncio
import os
import sys
import json
import time
import random
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_NTA_DIR = os.path.join(_HERE, "App", "NetworkTrafficAnalyzer")
if _NTA_DIR not in sys.path:
    sys.path.insert(0, _NTA_DIR)

try:
    from core.sniffer import CaptureEngine, format_packet, SCAPY_AVAILABLE, WELL_KNOWN_PORTS
    _ENGINE_AVAILABLE = SCAPY_AVAILABLE
except Exception:
    _ENGINE_AVAILABLE = False
    SCAPY_AVAILABLE   = False
    WELL_KNOWN_PORTS  = {}

# ── Simulation data ───────────────────────────────────────────────────────────
_SRC_SUBNETS     = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113."]
_DST_HOSTS       = ["8.8.8.8", "1.1.1.1", "192.168.1.1",
                    "104.21.14.1", "172.217.0.1", "151.101.0.1"]
_PROTO_POOL      = ["TCP", "TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
_TCP_FLAGS       = ["SYN", "ACK", "SYN-ACK", "PSH-ACK", "FIN-ACK", "RST"]
_KNOWN_PORTS     = [80, 443, 53, 22, 25, 3306, 8080, 8443, 3389, 5432]
_SUSPICIOUS_PORTS = {31337, 4444, 6666, 1337, 12345, 9999, 65535, 8888}


def _simulate_packets(n: int = 5) -> list:
    pkts = []
    for _ in range(n):
        proto    = random.choice(_PROTO_POOL)
        src_ip   = random.choice(_SRC_SUBNETS) + str(random.randint(1, 254))
        dst_ip   = random.choice(_DST_HOSTS)
        src_port = random.randint(1024, 65535)
        dst_port = (random.choice(_KNOWN_PORTS)
                    if random.random() < 0.75
                    else random.randint(1, 65535))
        flag     = random.choice(_TCP_FLAGS) if proto == "TCP" else "—"
        size     = random.randint(64, 1500)
        sus      = dst_port in _SUSPICIOUS_PORTS or src_port in _SUSPICIOUS_PORTS
        svc      = WELL_KNOWN_PORTS.get(dst_port, "")
        summary  = f"{flag} ({svc})" if svc else flag

        pkts.append({
            "src":        f"{src_ip}:{src_port}",
            "dst":        f"{dst_ip}:{dst_port}",
            "protocol":   proto,
            "flag":       flag,
            "summary":    summary,
            "bytes":      size,
            "suspicious": sus,
            "source":     "simulated",
            "ts":         datetime.utcnow().isoformat() + "Z",
        })
    return pkts


class _Stats:
    def __init__(self):
        self.total = 0; self.bytes = 0; self.sus = 0
        self.tcp = 0;   self.udp   = 0; self.other = 0
        self.hosts: set = set()

    def add(self, pkt: dict):
        self.total += 1
        self.bytes += pkt.get("bytes", 0)
        if pkt.get("suspicious"): self.sus += 1
        proto = pkt.get("protocol", "")
        if proto == "TCP":   self.tcp   += 1
        elif proto == "UDP": self.udp   += 1
        else:                self.other += 1
        src_ip = pkt.get("src", "").split(":")[0]
        if src_ip: self.hosts.add(src_ip)

    def to_dict(self) -> dict:
        t = max(self.total, 1)
        return {
            "total_packets": self.total,
            "total_bytes":   self.bytes,
            "suspicious":    self.sus,
            "unique_hosts":  len(self.hosts),
            "tcp_pct":       round(self.tcp   / t * 100),
            "udp_pct":       round(self.udp   / t * 100),
            "other_pct":     round(self.other / t * 100),
        }


# traffic_analyzer_api.py

def _matches_filters(pkt: dict, protocol: str, ip: str, src_ip: str, dst_ip: str) -> bool:
    """Return True if packet passes all active filters."""
    # Protocol filter
    if protocol:
        if pkt.get("protocol", "").upper() != protocol.upper():
            return False

    # Extract IPs from "src_ip:port" format
    pkt_src = pkt.get("src", "").rsplit(":", 1)[0]
    pkt_dst = pkt.get("dst", "").rsplit(":", 1)[0]

    # IP (src OR dst match)
    if ip:
        if ip not in pkt_src and ip not in pkt_dst:
            return False

    # Source IP filter
    if src_ip:
        if src_ip not in pkt_src:
            return False

    # Destination IP filter
    if dst_ip:
        if dst_ip not in pkt_dst:
            return False

    return True


async def stream_traffic(
    duration: int = 15,
    protocol: str = "",
    port:     str = "",
    ip:       str = "",
    src_ip:   str = "",
    dst_ip:   str = "",
):
    duration = max(5, min(60, duration))
    stats    = _Stats()
    end_at   = time.time() + duration
    tick     = 0

    while time.time() < end_at:
        if tick > 0:
            await asyncio.sleep(0.6)

        raw_batch = _simulate_packets(random.randint(3, 8))

        # Apply filters 
        batch = [
            pkt for pkt in raw_batch
            if _matches_filters(pkt, protocol, ip, src_ip, dst_ip)
        ]

        for pkt in batch:
            stats.add(pkt)

        payload = {
            "packets":  batch,
            "stats":    stats.to_dict(),
            "elapsed":  round(duration - (end_at - time.time()), 1),
            "duration": duration,
        }
        yield f"data: {json.dumps(payload)}\n\n"
        yield ": keepalive\n\n"

        tick += 1

    yield f"data: {json.dumps({'done': True, 'stats': stats.to_dict()})}\n\n"


def snapshot_traffic(count: int = 20, protocol: str = "", ip: str = "",
                     src_ip: str = "", dst_ip: str = "") -> dict:
    count    = max(1, min(50, count))
    packets  = []
    attempts = 0

    while len(packets) < count and attempts < 20:
        raw = _simulate_packets(max(count, 10))
        for p in raw:
            if _matches_filters(p, protocol, ip, src_ip, dst_ip):
                packets.append(p)
                if len(packets) >= count:
                    break
        attempts += 1

    packets = packets[:count]
    stats   = _Stats()
    for p in packets:
        stats.add(p)
    return {"packets": packets, "count": len(packets), "stats": stats.to_dict()}