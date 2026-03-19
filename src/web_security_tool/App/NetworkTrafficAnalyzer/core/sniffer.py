"""NetworkTraffic Analyzer - Packet capture module using Scapy."""

import os
import threading
import time
from datetime import datetime
from pathlib import Path
import ipaddress

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, AsyncSniffer, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _validate_ip(value: str, label: str) -> str:
    """Validate an IPv4/IPv6 address string. Returns normalized string."""
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError(f"Invalid {label} '{value}'. Enter a valid IP address.")


def build_bpf_filter(protocol="", port="", ip="", src_ip="", dst_ip=""):
    """
    Build a BPF filter string from protocol/port and IP filters.
    - ip: match either src or dst (host X)
    - src_ip: match src host X
    - dst_ip: match dst host X
    """
    parts = []

    protocol = (protocol or "").strip().lower()
    port = (port or "").strip()

    ip = _validate_ip(ip, "IP")
    src_ip = _validate_ip(src_ip, "Source IP")
    dst_ip = _validate_ip(dst_ip, "Destination IP")

    valid_protocols = ("tcp", "udp", "icmp", "")
    if protocol not in valid_protocols:
        raise ValueError(f"Invalid protocol '{protocol}'. Please enter TCP, UDP, or ICMP.")

    if protocol:
        parts.append(protocol)

    # IP filters
    if ip:
        parts.append(f"host {ip}")
    if src_ip:
        parts.append(f"src host {src_ip}")
    if dst_ip:
        parts.append(f"dst host {dst_ip}")

    # Port filter
    if port:
        if protocol == "icmp":
            raise ValueError("ICMP does not use ports. Remove the port filter.")
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError(f"Invalid port '{port}'. Enter a number between 1 and 65535.")
        parts.append(f"port {port_num}")

    return " and ".join(parts) if parts else ""

#def build_ip_filter(ip="", src_ip="", dst_ip=""):
    """Build BPF host/src/dst filters from IP fields (IPv4)."""

    #def is_ipv4(s: str) -> bool:
        #s = s.strip()
        #parts = s.split(".")
        #if len(parts) != 4:
            #return False
        #try:
            #return all(0 <= int(p) <= 255 for p in parts)
        #except ValueError:
            #return False

    #parts = []
    #ip = ip.strip()
    #src_ip = src_ip.strip()
    #dst_ip = dst_ip.strip()

    #if ip:
        #if not is_ipv4(ip):
            #raise ValueError(f"Invalid IP '{ip}'. Use IPv4 like 192.168.1.10")
        #parts.append(f"host {ip}")

    #if src_ip:
        #if not is_ipv4(src_ip):
            #raise ValueError(f"Invalid Source IP '{src_ip}'. Use IPv4 format.")
        #parts.append(f"src host {src_ip}")

    #if dst_ip:
        #if not is_ipv4(dst_ip):
            #raise ValueError(f"Invalid Destination IP '{dst_ip}'. Use IPv4 format.")
        #parts.append(f"dst host {dst_ip}")

    #return " and ".join(parts) if parts else ""


# Lookup tables for human-readable packet descriptions

TCP_FLAG_NAMES = {
    "S":   "SYN (Connection request)",
    "SA":  "SYN-ACK (Connection accepted)",
    "A":   "ACK",
    "PA":  "PSH-ACK (Data push)",
    "FA":  "FIN-ACK (Connection closing)",
    "F":   "FIN (Connection closing)",
    "R":   "RST (Connection reset)",
    "RA":  "RST-ACK (Connection reset)",
    "FPA": "FIN-PSH-ACK (Final data + close)",
    "SE":  "SYN-ECE (ECN capable)",
    "SEC": "SYN-ECE-CWR",
}

ICMP_TYPE_NAMES = {
    (0, 0):  "Echo Reply (Pong)",
    (3, 0):  "Destination Network Unreachable",
    (3, 1):  "Destination Host Unreachable",
    (3, 2):  "Protocol Unreachable",
    (3, 3):  "Port Unreachable",
    (3, 4):  "Fragmentation Needed",
    (3, 6):  "Destination Network Unknown",
    (3, 13): "Communication Administratively Filtered",
    (5, 0):  "Redirect (Network)",
    (5, 1):  "Redirect (Host)",
    (8, 0):  "Echo Request (Ping)",
    (11, 0): "TTL Expired in Transit",
    (11, 1): "Fragment Reassembly Time Exceeded",
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submit", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-Browser",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _port_label(port_num):
    """Return service name for a port, or empty string."""
    name = WELL_KNOWN_PORTS.get(port_num)
    return f" ({name})" if name else ""


def format_packet(packet):
    """Extract key details from a captured packet into a dict."""
    details = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "Other",
        "src_port": "",
        "dst_port": "",
        "summary": "",
    }

    if packet.haslayer(IP):
        details["src_ip"] = packet[IP].src
        details["dst_ip"] = packet[IP].dst

    if packet.haslayer(TCP):
        details["protocol"] = "TCP"
        details["src_port"] = str(packet[TCP].sport)
        details["dst_port"] = str(packet[TCP].dport)
        flags = str(packet[TCP].flags)
        flag_desc = TCP_FLAG_NAMES.get(flags, f"Flags: {flags}")
        svc = _port_label(packet[TCP].dport) or _port_label(packet[TCP].sport)
        details["summary"] = f"{flag_desc}{svc}"
    elif packet.haslayer(UDP):
        details["protocol"] = "UDP"
        details["src_port"] = str(packet[UDP].sport)
        details["dst_port"] = str(packet[UDP].dport)
        payload_len = len(packet[UDP].payload)
        svc = _port_label(packet[UDP].dport) or _port_label(packet[UDP].sport)
        details["summary"] = f"{payload_len} bytes{svc}"
    elif packet.haslayer(ICMP):
        details["protocol"] = "ICMP"
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        desc = ICMP_TYPE_NAMES.get((icmp_type, icmp_code), f"Type {icmp_type}, Code {icmp_code}")
        details["summary"] = desc
    else:
        details["summary"] = packet.summary()

    return details


def format_packet_line(details):
    """Format packet details dict into a single display line."""
    src = details["src_ip"]
    if details["src_port"]:
        src += f":{details['src_port']}"

    dst = details["dst_ip"]
    if details["dst_port"]:
        dst += f":{details['dst_port']}"

    return (
        f"[{details['timestamp']}] {details['protocol']} | "
        f"SRC: {src} | DST: {dst} | {details['summary']}"
    )


class CaptureEngine:
    """Manages packet capture in a background thread using AsyncSniffer."""

    def __init__(self, log_dir="logs"):
        self.running = False
        self.callback = None
        self.packets = []          # formatted dicts
        self._sniffer = None       # AsyncSniffer instance

        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)

        self._pcap_path = ""       # where we saved the pcap (after stop)
        self._raw_packets = []     # scapy packets for pcap

    def get_pcap_path(self):
        """Return last saved PCAP path (empty string if none)."""
        return self._pcap_path

    def start(self, protocol="", port="", ip="", src_ip="", dst_ip="", callback=None):
        """Start capturing packets with optional filters."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Please install it with:\n"
                "  pip install scapy\nThen restart the application."
            )

        # Build filter parts
        #bpf1 = build_bpf_filter(protocol, port)
        #bpf2 = build_ip_filter(ip, src_ip, dst_ip)
        #bpf_filter = " and ".join([p for p in (bpf1, bpf2) if p]).strip()

        bpf_filter = build_bpf_filter(
        protocol=protocol,
        port=port,
        ip=ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )

        self.callback = callback
        self.packets = []
        self._raw_packets = []
        self._pcap_path = ""
        self.running = True

        conf.verb = 0

        try:
            self._sniffer = AsyncSniffer(
                filter=bpf_filter if bpf_filter else None,
                prn=self._process_packet,
                store=False,
            )
            self._sniffer.start()
        except PermissionError:
            self.running = False
            raise
        except Exception as e:
            self.running = False
            raise RuntimeError(f"Capture failed to start: {e}")

    def _process_packet(self, packet):
        """Format a packet and send to callback."""
        if not self.running:
            return

        self._raw_packets.append(packet)

        details = format_packet(packet)
        self.packets.append(details)

        line = format_packet_line(details)
        if self.callback:
            self.callback(line)

    def _close_pcap(self):
        if self._pcap_writer is not None:
            try:
                self._pcap_writer.close()
            finally:
                self._pcap_writer = None

    def stop(self):
        """Stop capture (NO file writing here)."""
        if not self.running:
            return

        self.running = False

        try:
            if self._sniffer:
                self._sniffer.stop()
        except Exception:
            pass

    def export_pcap(self, out_dir=None):
        """
        Save captured packets as a PCAP file into out_dir (default: self.log_dir).
        Returns the saved pcap path, or "" if nothing saved.
        """
        out_dir = out_dir or self.log_dir
        os.makedirs(out_dir, exist_ok=True)

        if not self._raw_packets:
            self._pcap_path = ""
            return ""

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._pcap_path = os.path.join(out_dir, f"traffic_{ts}.pcap")

        wrpcap(self._pcap_path, self._raw_packets)
        self._raw_packets = []
        return self._pcap_path
