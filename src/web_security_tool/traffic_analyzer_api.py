"""
traffic_analyzer_api.py
Wraps MS2's CaptureEngine (core/sniffer.py) for FastAPI SSE streaming.
Falls back to simulation when Scapy / root privileges are unavailable.
"""

import os
import sys
import json
import time
import queue
import random
import threading
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))

_NTA_DIR = os.path.join(_HERE, "App", "NetworkTrafficAnalyzer")
if _NTA_DIR not in sys.path:
    sys.path.insert(0, _NTA_DIR)

# Try importing MS2's CaptureEngine
try:
    from core.sniffer import (
        CaptureEngine,
        format_packet,
        SCAPY_AVAILABLE,
        WELL_KNOWN_PORTS,
    )
    _ENGINE_AVAILABLE = SCAPY_AVAILABLE
except Exception:
    _ENGINE_AVAILABLE = False
    SCAPY_AVAILABLE = False
    WELL_KNOWN_PORTS = {}

# ── Suspicious ports (mirrors MS2 logic) ──────────────────────────────────────
_SUSPICIOUS_PORTS = {31337, 4444, 6666, 1337, 12345, 9999, 65535, 8888}

# ── Simulation data ───────────────────────────────────────────────────────────
_SRC_SUBNETS = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113."]
_DST_HOSTS   = ["8.8.8.8", "1.1.1.1", "192.168.1.1",
                "104.21.14.1", "172.217.0.1", "151.101.0.1"]
_PROTO_POOL  = ["TCP", "TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
_TCP_FLAGS   = ["SYN", "ACK", "SYN-ACK", "PSH-ACK", "FIN-ACK", "RST"]
_KNOWN_PORTS = [80, 443, 53, 22, 25, 3306, 8080, 8443, 3389, 5432]


def _simulate_packets(n: int = 5) -> list:
    """Generate n realistic fake packets for demo / Render use."""
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

        svc     = WELL_KNOWN_PORTS.get(dst_port, "")
        summary = f"{flag} ({svc})" if svc else flag

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


def _engine_packet_to_dict(details: dict) -> dict:
    """Convert a CaptureEngine format_packet dict to the frontend shape."""
    src_port = details.get("src_port", "")
    dst_port = details.get("dst_port", "")
    src = details["src_ip"] + (f":{src_port}" if src_port else "")
    dst = details["dst_ip"] + (f":{dst_port}" if dst_port else "")

    try:
        dst_port_int = int(dst_port) if dst_port else 0
        src_port_int = int(src_port) if src_port else 0
    except ValueError:
        dst_port_int = src_port_int = 0

    suspicious = (
        dst_port_int in _SUSPICIOUS_PORTS or
        src_port_int in _SUSPICIOUS_PORTS
    )

    return {
        "src":        src,
        "dst":        dst,
        "protocol":   details.get("protocol", "Other"),
        "flag":       details.get("summary", ""),
        "summary":    details.get("summary", ""),
        "bytes":      random.randint(64, 1500),
        "suspicious": suspicious,
        "source":     "live",
        "ts":         details.get("timestamp", datetime.utcnow().isoformat()),
    }


# ── Stats accumulator ─────────────────────────────────────────────────────────

class _Stats:
    def __init__(self):
        self.total = 0
        self.bytes = 0
        self.sus   = 0
        self.tcp   = 0
        self.udp   = 0
        self.other = 0
        self.hosts: set = set()

    def add(self, pkt: dict):
        self.total += 1
        self.bytes += pkt.get("bytes", 0)
        if pkt.get("suspicious"):
            self.sus += 1
        proto = pkt.get("protocol", "")
        if proto == "TCP":        self.tcp   += 1
        elif proto == "UDP":      self.udp   += 1
        else:                     self.other += 1
        src_ip = pkt.get("src", "").split(":")[0]
        if src_ip:
            self.hosts.add(src_ip)

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


# ── Public functions ───────────────────────────────────────────────────────────

def stream_traffic(
    duration: int = 15,
    protocol: str = "",
    port:     str = "",
    ip:       str = "",
    src_ip:   str = "",
    dst_ip:   str = "",
):
    """
    Generator that yields SSE-formatted strings for `duration` seconds.
    Uses MS2 CaptureEngine when Scapy + privileges are available,
    otherwise falls back to simulation (safe for Render / Windows non-admin).

    Yields strings like:  "data: {...json...}\\n\\n"
    """
    duration = max(5, min(60, duration))
    stats    = _Stats()
    end_at   = time.time() + duration
    use_live = _ENGINE_AVAILABLE

    # ── Try live capture via MS2 CaptureEngine ────────────────────────────
    if use_live:
        pkt_queue: queue.Queue = queue.Queue()
        engine = CaptureEngine(log_dir=os.path.join(_HERE, "logs"))

        # Intercept _process_packet to push dicts into our queue
        def _intercepted(packet):
            try:
                details  = format_packet(packet)
                pkt_dict = _engine_packet_to_dict(details)
                pkt_queue.put(pkt_dict)
            except Exception:
                pass

        engine._process_packet = _intercepted

        try:
            engine.start(
                protocol=protocol,
                port=port,
                ip=ip,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        except Exception:
            use_live = False

    # ── Streaming loop ────────────────────────────────────────────────────
    try:
        while time.time() < end_at:
            batch = []

            if use_live:
                deadline = time.time() + 0.5
                while time.time() < deadline:
                    try:
                        pkt = pkt_queue.get(timeout=0.05)
                        batch.append(pkt)
                    except queue.Empty:
                        pass
            else:
                batch = _simulate_packets(random.randint(3, 8))
                time.sleep(0.5)

            for pkt in batch:
                stats.add(pkt)

            payload = {
                "packets":  batch,
                "stats":    stats.to_dict(),
                "elapsed":  round(duration - (end_at - time.time()), 1),
                "duration": duration,
            }
            yield f"data: {json.dumps(payload)}\n\n"

    finally:
        if use_live:
            try:
                engine.stop()
            except Exception:
                pass

    # ── Done frame ────────────────────────────────────────────────────────
    yield f"data: {json.dumps({'done': True, 'stats': stats.to_dict()})}\n\n"


def snapshot_traffic(count: int = 20) -> dict:
    """
    Single-shot non-streaming packet snapshot.
    Always uses simulation — suitable for quick demos.
    """
    count   = max(1, min(50, count))
    packets = _simulate_packets(count)
    stats   = _Stats()
    for p in packets:
        stats.add(p)
    return {
        "packets": packets,
        "count":   len(packets),
        "stats":   stats.to_dict(),
    }