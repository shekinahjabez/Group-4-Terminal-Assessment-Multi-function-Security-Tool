"""Port Scanner - TCP port scanning module."""

import socket
import threading
from datetime import datetime


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


def validate_hostname(hostname):
    """Validate and resolve a hostname or IP address.

    Returns:
        tuple: (is_valid, resolved_ip_or_error_message)
    """
    if not hostname or hostname.strip() == "":
        return False, "Please enter a valid IP address or hostname."

    hostname = hostname.strip()

    try:
        ip = socket.gethostbyname(hostname)
        return True, ip
    except socket.gaierror:
        return False, "Host unreachable or DNS failure. Cannot resolve hostname."
    except Exception as e:
        return False, f"Invalid hostname or IP address. {e}"


def validate_port_range(start_str, end_str):
    """Validate start and end port strings.

    Returns:
        tuple: (is_valid, start_port, end_port, error_message)
    """
    if not start_str or not end_str:
        return False, 0, 0, "Please enter both start and end ports."

    try:
        start = int(start_str.strip())
        end = int(end_str.strip())
    except ValueError:
        return False, 0, 0, "Port numbers must be integers."

    if not 1 <= start <= 65535:
        return False, 0, 0, "Start port must be between 1 and 65535."
    if not 1 <= end <= 65535:
        return False, 0, 0, "End port must be between 1 and 65535."
    if start >= end:
        return False, 0, 0, "Start port must be less than end port."

    return True, start, end, ""


def scan_port(host, port, timeout=0.7):
    """Scan a single TCP port.

    Returns:
        bool: True if port is open, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.gaierror, socket.error, OSError):
        return False


def format_result_line(port, is_open):
    """Format a scan result into a display line."""
    status = "OPEN" if is_open else "CLOSED"
    svc = _port_label(port)
    timestamp = datetime.now().strftime("%H:%M:%S")
    return f"[{timestamp}] Port {port}{svc}: {status}"


class ScanEngine:
    """Manages port scanning in a background daemon thread."""

    def __init__(self):
        self.running = False
        self.callback = None
        self._thread = None
        self.open_ports = []

    def start(self, host, start_port, end_port, timeout=0.7, callback=None):
        """Start scanning ports in a background thread.

        Args:
            host: Resolved IP address or hostname.
            start_port: First port to scan.
            end_port: Last port to scan (inclusive).
            timeout: Socket timeout per port in seconds.
            callback: Function called with (port, is_open, line) for each result.
        """
        if self.running:
            raise RuntimeError("A scan is already in progress.")

        self.running = True
        self.callback = callback
        self.open_ports = []

        self._thread = threading.Thread(
            target=self._scan_loop,
            args=(host, start_port, end_port, timeout),
            daemon=True,
        )
        self._thread.start()

    def _scan_loop(self, host, start_port, end_port, timeout):
        """Scan loop running in daemon thread."""
        try:
            for port in range(start_port, end_port + 1):
                if not self.running:
                    if self.callback:
                        self.callback(0, False, "[INFO] Scan cancelled by user.")
                    break

                is_open = scan_port(host, port, timeout)
                if is_open:
                    self.open_ports.append(port)

                line = format_result_line(port, is_open)
                if self.callback:
                    self.callback(port, is_open, line)
            else:
                if self.running and self.callback:
                    summary = (
                        f"\n{'=' * 50}\n"
                        f"Scan complete. {len(self.open_ports)} open port(s) found."
                    )
                    if self.open_ports:
                        summary += (
                            f"\nOpen ports: "
                            f"{', '.join(str(p) + _port_label(p) for p in self.open_ports)}"
                        )
                    summary += f"\n{'=' * 50}"
                    self.callback(0, False, summary)
        except Exception as e:
            if self.callback:
                self.callback(0, False, f"[ERROR] Scan failed: {e}")
        finally:
            self.running = False

    def stop(self):
        """Signal the scan thread to stop."""
        self.running = False
