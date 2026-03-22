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
    from core.sniffer import CaptureEngine, format_packet, SCAPY_AVAILABLE, WELL_KNOWN_PORTS, build_bpf_filter
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


# ── Live packet formatter ──────────────────────────────────────────────────────

_SCAPY_FLAG_MAP = {
    "S":   "SYN",
    "SA":  "SYN-ACK",
    "A":   "ACK",
    "PA":  "PSH-ACK",
    "FA":  "FIN-ACK",
    "F":   "FIN",
    "R":   "RST",
    "RA":  "RST-ACK",
}


def _format_live_packet(packet) -> dict:
    """Convert a raw Scapy packet to the SSE packet dict (same schema as _simulate_packets)."""
    from scapy.all import IP, TCP, UDP, ICMP

    ts = datetime.utcnow().isoformat() + "Z"

    # C-7: Non-IP packets (ARP, STP, raw Ethernet) — return safe fallback
    if not packet.haslayer(IP):
        return {
            "src":        "non-IP",
            "dst":        "non-IP",
            "protocol":   "Other",
            "flag":       "—",
            "summary":    packet.summary(),
            "bytes":      len(packet),
            "suspicious": False,
            "source":     "live",
            "ts":         ts,
        }

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    src_port = 0
    dst_port = 0
    protocol = "Other"
    flag     = "—"
    summary  = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        raw_flag = str(packet[TCP].flags)
        flag     = _SCAPY_FLAG_MAP.get(raw_flag, raw_flag) if raw_flag else "—"
        svc      = WELL_KNOWN_PORTS.get(dst_port, "") or WELL_KNOWN_PORTS.get(src_port, "")
        summary  = f"{flag} ({svc})" if svc else flag

    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        svc      = WELL_KNOWN_PORTS.get(dst_port, "") or WELL_KNOWN_PORTS.get(src_port, "")
        summary  = f"UDP ({svc})" if svc else "UDP"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        summary  = f"ICMP type={packet[ICMP].type} code={packet[ICMP].code}"

    else:
        summary = packet.summary()

    suspicious = dst_port in _SUSPICIOUS_PORTS or src_port in _SUSPICIOUS_PORTS
    src_str    = f"{src_ip}:{src_port}" if src_port else src_ip
    dst_str    = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

    return {
        "src":        src_str,
        "dst":        dst_str,
        "protocol":   protocol,
        "flag":       flag,
        "summary":    summary,
        "bytes":      len(packet),
        "suspicious": suspicious,
        "source":     "live",
        "ts":         ts,
    }


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

def _matches_filters(pkt: dict, protocol: str, ip: str, src_ip: str, dst_ip: str, port: str = "") -> bool:
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

    # Port filter (src OR dst port match)
    if port:
        try:
            p = int(port)
            pkt_src_port = int(pkt.get("src", "").rsplit(":", 1)[-1])
            pkt_dst_port = int(pkt.get("dst", "").rsplit(":", 1)[-1])
            if pkt_src_port != p and pkt_dst_port != p:
                return False
        except (ValueError, IndexError):
            pass  # malformed port — skip filter rather than crash

    return True


# ── Live capture stream ────────────────────────────────────────────────────────

async def _stream_live(
    duration: int,
    protocol: str,
    port:     str,
    ip:       str,
    src_ip:   str,
    dst_ip:   str,
    iface:    str = "",
):
    """Async generator: real packet capture via Scapy AsyncSniffer."""
    # 2a: Build BPF filter — validate user inputs early
    try:
        bpf_filter = build_bpf_filter(
            protocol=protocol, port=port,
            ip=ip, src_ip=src_ip, dst_ip=dst_ip,
        )
    except ValueError as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"
        return

    # Default to IP-only when no user filters given (C-7: exclude ARP/STP noise)
    bpf_filter = bpf_filter or "ip"

    # 2b: asyncio/thread bridge — C-1: get_running_loop(), C-2: bounded queue
    loop  = asyncio.get_running_loop()
    queue = asyncio.Queue(maxsize=500)

    # 2c: per-packet callback runs on sniffer thread
    def _on_packet(pkt):
        item = _format_live_packet(pkt)
        try:
            loop.call_soon_threadsafe(queue.put_nowait, item)
        except asyncio.QueueFull:
            pass  # C-2: drop packet rather than block sniffer thread

    # 2d: start sniffer — handle all failure modes (C-6: OSError for missing Npcap)
    from scapy.all import AsyncSniffer, conf as scapy_conf
    scapy_conf.verb = 0

    try:
        sniffer = AsyncSniffer(
            filter=bpf_filter,
            iface=iface if iface else None,
            prn=_on_packet,
            store=False,
        )
        sniffer.start()
        # Scapy defers interface/permission errors to the background thread.
        # Wait briefly so the thread has time to fail, then surface the error early.
        await asyncio.sleep(0.15)
        if getattr(sniffer, 'exception', None):
            raise sniffer.exception
    except PermissionError:
        yield f"data: {json.dumps({'error': 'Permission denied. Run the agent with sudo or grant cap_net_raw.'})}\n\n"
        return
    except OSError as e:
        # C-6: Windows raises OSError when Npcap/WinPcap is missing; also bad iface on Linux
        yield f"data: {json.dumps({'error': f'Capture failed to start: {e}'})}\n\n"
        return
    except ValueError as e:
        # Bad interface name raises ValueError inside Scapy's background thread
        yield f"data: {json.dumps({'error': f'Capture failed to start: {e}'})}\n\n"
        return
    except Exception as e:
        yield f"data: {json.dumps({'error': f'Unexpected error starting capture: {e}'})}\n\n"
        return

    # 2e/2f/2g/2h: drain loop with cancellation-safe finally (C-5)
    stats         = _Stats()
    end_at        = time.time() + duration
    batch         = []
    last_yield_at = time.time()

    try:
        while time.time() < end_at:
            try:
                pkt = await asyncio.wait_for(queue.get(), timeout=0.5)
                batch.append(pkt)
                stats.add(pkt)
            except asyncio.TimeoutError:
                pass  # quiet network — keep looping

            now = time.time()
            if now - last_yield_at >= 0.6:
                payload = {
                    "packets":  batch,
                    "stats":    stats.to_dict(),
                    "elapsed":  round(duration - (end_at - now), 1),
                    "duration": duration,
                    "mode":     "live",
                }
                yield f"data: {json.dumps(payload)}\n\n"
                yield ": keepalive\n\n"
                batch         = []
                last_yield_at = now

        # 2f: flush any packets that arrived in the final window
        if batch:
            now = time.time()
            payload = {
                "packets":  batch,
                "stats":    stats.to_dict(),
                "elapsed":  duration,
                "duration": duration,
                "mode":     "live",
            }
            yield f"data: {json.dumps(payload)}\n\n"

        # 2g: done message
        yield f"data: {json.dumps({'done': True, 'stats': stats.to_dict(), 'mode': 'live'})}\n\n"

    except asyncio.CancelledError:
        # C-5: re-raise after cleanup so uvicorn knows the task was cancelled
        raise
    finally:
        # C-5: always runs — even on client disconnect or CancelledError.
        # Wrap stop() because Scapy re-raises background thread exceptions here
        # (e.g. bad interface name raises ValueError inside stop()).
        try:
            sniffer.stop()
        except Exception:
            pass


async def stream_traffic(
    duration: int = 15,
    protocol: str = "",
    port:     str = "",
    ip:       str = "",
    src_ip:   str = "",
    dst_ip:   str = "",
    use_real: bool = False,
    iface:    str  = "",
):
    # Dispatch to live capture path when requested and Scapy is available
    if use_real and _ENGINE_AVAILABLE:
        async for chunk in _stream_live(duration, protocol, port, ip, src_ip, dst_ip, iface):
            yield chunk
        return

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
            if _matches_filters(pkt, protocol, ip, src_ip, dst_ip, port)
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
                     src_ip: str = "", dst_ip: str = "", port: str = "") -> dict:
    count    = max(1, min(50, count))
    packets  = []
    attempts = 0

    while len(packets) < count and attempts < 20:
        raw = _simulate_packets(max(count, 10))
        for p in raw:
            if _matches_filters(p, protocol, ip, src_ip, dst_ip, port):
                packets.append(p)
                if len(packets) >= count:
                    break
        attempts += 1

    packets = packets[:count]
    stats   = _Stats()
    for p in packets:
        stats.add(p)
    return {"packets": packets, "count": len(packets), "stats": stats.to_dict()}