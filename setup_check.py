"""
setup_check.py — SecureKit Local Agent Environment Checker
Run this before starting local_agent.py for the first time.
Usage:
    python setup_check.py           # check only
    python setup_check.py --install # check and auto-install missing packages
"""
import sys
import os
import platform
import importlib
import importlib.metadata
import subprocess
import argparse

_USE_COLOR = sys.stdout.isatty() and platform.system() != "Windows"

def _c(code, text): return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

OK   = lambda t: _c("32;1", f"  [OK]   {t}")
WARN = lambda t: _c("33;1", f"  [WARN] {t}")
FAIL = lambda t: _c("31;1", f"  [FAIL] {t}")
INFO = lambda t: _c("36",   f"  [INFO] {t}")
HEAD = lambda t: _c("1",    f"\n{t}")


def check_python() -> bool:
    v = sys.version_info
    if v >= (3, 9):
        print(OK(f"Python {v.major}.{v.minor}.{v.micro}"))
        return True
    print(FAIL(f"Python {v.major}.{v.minor}.{v.micro} — requires 3.9 or higher"))
    return False


def check_package(pkg_import: str, pip_name: str, install: bool) -> bool:
    try:
        importlib.import_module(pkg_import)
        try:
            ver = importlib.metadata.version(pip_name)
            print(OK(f"{pip_name} {ver}"))
        except Exception:
            print(OK(f"{pip_name} (version unknown)"))
        return True
    except ImportError:
        if install:
            print(WARN(f"{pip_name} not found — installing…"))
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print(OK(f"{pip_name} installed successfully"))
                return True
            else:
                print(FAIL(f"{pip_name} install failed:\n{result.stderr.strip()}"))
                return False
        else:
            print(FAIL(f"{pip_name} not installed → run: pip install {pip_name}"))
            return False


def check_scapy_import() -> bool:
    try:
        from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
        print(OK("Scapy import successful (AsyncSniffer, IP, TCP, UDP, ICMP)"))
        return True
    except ImportError as e:
        print(FAIL(f"Scapy import failed: {e}"))
        return False


def check_privileges() -> bool:
    system = platform.system()
    if system in ("Linux", "Darwin"):
        is_root = os.geteuid() == 0
        if is_root:
            print(OK("Running as root — live packet capture available"))
        else:
            print(WARN(
                "Not running as root — port scanner will work, "
                "but live Scapy capture requires: sudo python local_agent.py"
            ))
        return True
    elif system == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            print(OK("Running as Administrator — live packet capture available"))
        else:
            print(WARN(
                "Not running as Administrator — "
                "right-click terminal → Run as Administrator for live capture"
            ))
        return True
    else:
        print(INFO(f"Unknown OS: {system} — privilege check skipped"))
        return True


def check_local_agent_file() -> bool:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_agent.py")
    if os.path.isfile(path):
        print(OK(f"local_agent.py found at {path}"))
        return True
    print(FAIL(f"local_agent.py not found at {path}"))
    return False


def main():
    parser = argparse.ArgumentParser(description="SecureKit Local Agent environment checker")
    parser.add_argument("--install", action="store_true",
                        help="Auto-install missing Python packages with pip")
    args = parser.parse_args()

    print(_c("1;36", "\n  SecureKit Local Agent — Environment Check"))
    print("  " + "─" * 50)

    results = {}

    print(HEAD("Python"))
    results["python"] = check_python()

    print(HEAD("Required packages"))
    results["fastapi"]   = check_package("fastapi",  "fastapi",  args.install)
    results["uvicorn"]   = check_package("uvicorn",  "uvicorn",  args.install)
    results["pydantic"]  = check_package("pydantic", "pydantic", args.install)
    results["scapy_pkg"] = check_package("scapy",    "scapy",    args.install)

    print(HEAD("Scapy runtime check"))
    results["scapy_import"] = check_scapy_import() if results["scapy_pkg"] else False

    print(HEAD("Privileges"))
    results["privileges"] = check_privileges()

    print(HEAD("Agent file"))
    results["agent_file"] = check_local_agent_file()

    print("\n  " + "─" * 50)

    blocking = [k for k in ("python", "fastapi", "uvicorn", "pydantic", "agent_file")
                if not results.get(k)]

    if blocking:
        print(_c("31;1", f"\n  SETUP INCOMPLETE — fix the issues above before starting the agent."))
        print(_c("33",   f"  Blocking items: {', '.join(blocking)}"))
        sys.exit(1)
    else:
        scapy_ok = results.get("scapy_import", False)
        print(_c("32;1", "\n  All required dependencies are installed."))
        if scapy_ok:
            print(_c("36", "  Start the agent with:"))
            if platform.system() == "Windows":
                print(_c("1", "    python local_agent.py  (Administrator terminal)"))
            else:
                print(_c("1", "    sudo python local_agent.py  (for live capture)"))
        else:
            print(_c("33", "  Scapy not available — only port scanning will work."))
            print(_c("1",  "  Start the agent with:"))
            print(_c("1",  "    python local_agent.py"))
        print()
    sys.exit(0)


if __name__ == "__main__":
    main()