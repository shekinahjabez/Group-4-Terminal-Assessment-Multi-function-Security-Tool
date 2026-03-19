#!/usr/bin/env python3
"""NetworkTraffic Analyzer - Entry point (PortableApps.com Format 3.9)."""

import sys
import os
import shutil
import time

# Path resolution for both source and PyInstaller execution
if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
    BUNDLE_DIR = sys._MEIPASS
    sys.path.insert(0, BUNDLE_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR
    sys.path.insert(0, APP_DIR)

# App/NetworkTrafficAnalyzer/ -> App/ -> NetworkTrafficAnalyzerPortable/
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
os.environ["NTA_DATA_DIR"] = DATA_DIR
os.environ["NTA_APP_DIR"] = APP_DIR
os.environ["NTA_PORTABLE_ROOT"] = PORTABLE_ROOT
os.environ["NTA_LOG_DIR"] = os.path.join(DATA_DIR, "logs")


# --- Dependency Auto-Install (bundled offline in App/Dependencies/) ---

DEPENDENCIES_DIR = os.path.join(PORTABLE_ROOT, "App", "Dependencies")

# (import_name, pip_spec, description, wheel_glob_pattern)
_PIP_DEPENDENCIES = [
    ("scapy", "scapy>=2.5.0", "Packet capture library", "scapy-*.whl"),
]


def _is_npcap_installed():
    """Check if Npcap/WinPcap is installed (Windows only)."""
    if sys.platform != "win32":
        return True
    npcap_dir = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap"
    )
    system32 = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32"
    )
    for search_dir in (npcap_dir, system32):
        if os.path.isfile(os.path.join(search_dir, "wpcap.dll")):
            return True
    return False


def _find_bundled_npcap():
    """Find bundled Npcap installer in App/Dependencies/."""
    if not os.path.isdir(DEPENDENCIES_DIR):
        return None
    installers = sorted(
        [f for f in os.listdir(DEPENDENCIES_DIR)
         if f.lower().startswith("npcap-") and f.lower().endswith(".exe")],
        reverse=True,
    )
    return os.path.join(DEPENDENCIES_DIR, installers[0]) if installers else None


def _find_bundled_wheel(glob_pattern):
    """Find bundled wheel file in App/Dependencies/."""
    import fnmatch
    if not os.path.isdir(DEPENDENCIES_DIR):
        return None
    matches = sorted(
        [f for f in os.listdir(DEPENDENCIES_DIR)
         if fnmatch.fnmatch(f.lower(), glob_pattern.lower())],
        reverse=True,
    )
    return os.path.join(DEPENDENCIES_DIR, matches[0]) if matches else None


def _check_missing_dependencies():
    """Return dict of missing pip packages and npcap status."""
    missing = {"pip": [], "npcap": False}

    if not getattr(sys, 'frozen', False):
        for module_name, pip_spec, description, wheel_pattern in _PIP_DEPENDENCIES:
            try:
                __import__(module_name)
            except ImportError:
                missing["pip"].append((module_name, pip_spec, description, wheel_pattern))

    if not _is_npcap_installed():
        missing["npcap"] = True

    return missing


def _build_missing_message(missing):
    """Build user-friendly message listing missing dependencies."""
    lines = ["The following dependencies are missing:\n"]

    for module_name, pip_spec, description, wheel_pattern in missing["pip"]:
        wheel = _find_bundled_wheel(wheel_pattern)
        if wheel:
            lines.append(f"  - {pip_spec}  ({description})")
            lines.append(f"    Bundled: {os.path.basename(wheel)}")
        else:
            lines.append(f"  - {pip_spec}  ({description})")
            lines.append(f"    WARNING: No bundled wheel found — requires internet")

    if missing["npcap"]:
        npcap_installer = _find_bundled_npcap()
        if npcap_installer:
            lines.append(f"  - Npcap  (Windows packet capture driver)")
            lines.append(f"    Bundled: {os.path.basename(npcap_installer)}")
        else:
            lines.append("  - Npcap  (Windows packet capture driver)")
            lines.append("    WARNING: No bundled installer found in App/Dependencies/")

    lines.append("")

    steps = []
    if missing["pip"]:
        steps.append("Install Python packages from bundled files")
    if missing["npcap"]:
        steps.append("Run the bundled Npcap installer (requires admin)")

    if len(steps) > 1:
        lines.append("The installer will:")
        for i, step in enumerate(steps, 1):
            lines.append(f"  {i}. {step}")
    else:
        lines.append(f"The installer will: {steps[0]}")

    lines.append("\nAll dependencies are bundled — no internet required.")
    return "\n".join(lines)


def _install_dependencies(missing):
    """Install missing deps from bundled files. Returns True on success."""
    import subprocess
    success = True

    if missing["pip"]:
        for module_name, pip_spec, description, wheel_pattern in missing["pip"]:
            wheel_path = _find_bundled_wheel(wheel_pattern)
            if wheel_path:
                print(f"Installing {module_name} from bundled wheel: "
                      f"{os.path.basename(wheel_path)}")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--no-index", "--find-links", DEPENDENCIES_DIR,
                     wheel_path],
                )
            else:
                print(f"No bundled wheel for {module_name}, trying online...")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pip_spec],
                )

            if result.returncode == 0:
                print(f"{module_name} installed successfully.\n")
            else:
                print(f"Failed to install {module_name}.")
                print(f"  Try manually: pip install {wheel_path or pip_spec}")
                success = False

    if missing["npcap"]:
        npcap_installer = _find_bundled_npcap()
        if npcap_installer:
            print(f"Running bundled Npcap installer: {os.path.basename(npcap_installer)}")
            print("Please follow the Npcap installation wizard...\n")
            try:
                result = subprocess.run([npcap_installer], check=False)
                if result.returncode == 0:
                    print("Npcap installed successfully.\n")
                else:
                    print(f"Npcap installer error. Run manually:\n  {npcap_installer}\n")
                    success = False
            except OSError as e:
                print(f"Failed to launch Npcap installer: {e}")
                print(f"Run manually:\n  {npcap_installer}\n")
                success = False
        else:
            print("No bundled Npcap installer found.")
            print("Download from https://npcap.com or place installer in App/Dependencies/\n")
            success = False

    return success


def _prompt_and_install(missing):
    """Prompt user (GUI or CLI) and install if they agree."""
    message = _build_missing_message(missing)

    if "--cli" in sys.argv:
        print(f"\n{message}")
        answer = input("\nInstall now? [Y/n]: ").strip().lower()
        if answer in ("", "y", "yes"):
            return _install_dependencies(missing)
        return False

    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        yes = messagebox.askyesno(
            "Missing Dependencies",
            message + "\n\nWould you like to install now?",
        )
        root.destroy()
        if yes:
            return _install_dependencies(missing)
        return False
    except Exception:
        print(f"\n{message}")
        answer = input("\nInstall now? [Y/n]: ").strip().lower()
        if answer in ("", "y", "yes"):
            return _install_dependencies(missing)
        return False


def check_dependencies():
    """Check all dependencies and offer to install if missing."""
    missing = _check_missing_dependencies()
    if not missing["pip"] and not missing["npcap"]:
        return True
    return _prompt_and_install(missing)


# --- Application Modes ---

def run_cli():
    """CLI mode for headless environments."""
    from core.sniffer import CaptureEngine, SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        print("Error: Scapy is not installed.")
        sys.exit(1)

    print("=" * 60)
    print("  NetworkTraffic Analyzer - Portable Edition (CLI)")
    print("=" * 60)
    print(f"  Data directory: {DATA_DIR}")
    print(f"  Logs directory: {os.environ.get('NTA_LOG_DIR')}")
    print("=" * 60)

    protocol = input("\nFilter by protocol (tcp/udp/icmp or Enter for all): ").strip()
    port = input("Filter by port (or Enter for any): ").strip()

    ip_any = input("Filter by IP (matches src OR dst, Enter for any): ").strip()
    src_ip = input("Filter by Source IP (Enter for any): ").strip()
    dst_ip = input("Filter by Destination IP (Enter for any): ").strip()

    engine = CaptureEngine(log_dir=os.environ.get("NTA_LOG_DIR", os.path.join(DATA_DIR, "logs")))

    try:
        engine.start(
            protocol=protocol,
            port=port,
            ip=ip_any,
            src_ip=src_ip,
            dst_ip=dst_ip,
            callback=print
        )
        print("\nCapture started... Press Ctrl+C to stop.\n")

        while engine.running:
            time.sleep(0.2)

    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        engine.stop()
        print("\nCapture stopped.")
        if hasattr(engine, "get_pcap_path"):
            print("Saved PCAP:", engine.get_pcap_path())


def run_gui():
    """Launch the Tkinter GUI."""
    from gui.app import main
    main()


if __name__ == "__main__":
    if not check_dependencies():
        sys.exit(1)

    if "--cli" in sys.argv:
        run_cli()
    else:
        run_gui()