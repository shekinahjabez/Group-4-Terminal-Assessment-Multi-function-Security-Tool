#!/usr/bin/env python3
"""Port Scanner - Entry point (PortableApps.com Format 3.9).

Author: Leonardo Arellano
"""

import sys
import os
import shutil

# Path resolution for both source and PyInstaller execution
if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
    BUNDLE_DIR = sys._MEIPASS
    sys.path.insert(0, BUNDLE_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR
    sys.path.insert(0, APP_DIR)

# App/PortScanner/ -> App/ -> PortScannerPortable/
PORTABLE_ROOT = os.path.dirname(os.path.dirname(APP_DIR))
DATA_DIR = os.path.join(PORTABLE_ROOT, "Data")
DEFAULT_DATA_DIR = os.path.join(PORTABLE_ROOT, "App", "DefaultData")


def initialize_data_directory():
    """Create Data/ from DefaultData/ template if missing."""
    if not os.path.exists(DATA_DIR):
        if os.path.exists(DEFAULT_DATA_DIR):
            shutil.copytree(DEFAULT_DATA_DIR, DATA_DIR)
        else:
            os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
            os.makedirs(os.path.join(DATA_DIR, "settings"), exist_ok=True)
    else:
        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
        os.makedirs(os.path.join(DATA_DIR, "settings"), exist_ok=True)


initialize_data_directory()
os.environ["PS_DATA_DIR"] = DATA_DIR
os.environ["PS_APP_DIR"] = APP_DIR
os.environ["PS_PORTABLE_ROOT"] = PORTABLE_ROOT


# --- Application Modes ---

def run_cli():
    """CLI mode for headless environments."""
    from core.scanner import (
        validate_hostname, validate_port_range, scan_port,
        format_result_line, WELL_KNOWN_PORTS, _port_label,
    )

    print("=" * 60)
    print("  Port Scanner - Portable Edition (CLI)")
    print("=" * 60)
    print(f"  Data directory: {DATA_DIR}")
    print("=" * 60)

    host = input("\nTarget host (IP or hostname): ").strip()
    valid, result = validate_hostname(host)
    if not valid:
        print(f"Error: {result}")
        sys.exit(1)
    print(f"Resolved: {result}")

    start_str = input("Start port (default 1): ").strip() or "1"
    end_str = input("End port (default 1024): ").strip() or "1024"

    valid, start_port, end_port, err = validate_port_range(start_str, end_str)
    if not valid:
        print(f"Error: {err}")
        sys.exit(1)

    print(f"\nScanning {result} ports {start_port}-{end_port}...\n")

    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            is_open = scan_port(result, port)
            line = format_result_line(port, is_open)
            print(line)
            if is_open:
                open_ports.append(port)
    except KeyboardInterrupt:
        print("\nScan cancelled.")

    print(f"\n{'=' * 50}")
    print(f"Scan complete. {len(open_ports)} open port(s) found.")
    if open_ports:
        print(f"Open ports: {', '.join(str(p) + _port_label(p) for p in open_ports)}")
    print("=" * 50)


def run_gui():
    """Launch the Tkinter GUI."""
    from gui.app import main
    main()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        run_cli()
    else:
        run_gui()
