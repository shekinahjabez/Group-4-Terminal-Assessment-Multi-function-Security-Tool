"""
local_agent.py — SecureKit MS2 Local Agent

Runs on the developer's machine. The Render frontend detects and uses
this agent for real TCP port scanning and live Scapy packet capture.

First-time setup:
    python setup_check.py           # verify environment
    python setup_check.py --install # verify + auto-install

Start the agent:
    sudo python local_agent.py      # Linux/macOS — enables live capture
    python local_agent.py           # Windows Admin terminal
    python local_agent.py           # port scanning only (no live capture)
"""

import os
import sys
import platform

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR  = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# Import the existing backend functions
try:
    from web_security_tool.port_scanner_api import run_scan
except ImportError:
    # Fallback: try alternate import paths
    try:
        sys.path.insert(0, os.path.join(BASE_DIR, "src", "web_security_tool"))
        from port_scanner_api import run_scan
    except ImportError:
        run_scan = None

try:
    from web_security_tool.traffic_analyzer_api import stream_traffic, _ENGINE_AVAILABLE
except ImportError:
    try:
        from traffic_analyzer_api import stream_traffic, _ENGINE_AVAILABLE
    except ImportError:
        stream_traffic     = None
        _ENGINE_AVAILABLE  = False


def _is_privileged() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        # Root check (Linux and macOS)
        if os.geteuid() == 0:
            return True
        # Linux capability check: try opening a raw packet socket.
        # Succeeds when cap_net_raw is granted via setcap even without root.
        if platform.system() == "Linux":
            import socket as _socket
            s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, 0)
            s.close()
            return True
    except (PermissionError, OSError, AttributeError, Exception):
        pass
    return False


_PRIVILEGED = _is_privileged()
_OS         = platform.system().lower()
_AGENT_VER  = "1.0.0"

app = FastAPI(
    title       = "SecureKit Local Agent",
    description = "MS2 local execution agent — runs on developer's machine",
    version     = _AGENT_VER,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Production frontend (render.yaml: name: securekit)
        "https://securekit.onrender.com",
        # Alternative Render deployment URL
        "https://securekit-whk3.onrender.com",
        # Fallback / legacy service names
        "https://securekit-ta.onrender.com",
        "https://milestone-1-web-security-tool-group-4.onrender.com",
        # Local development
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    """Probed by the frontend on component mount."""
    scapy_error = None
    if not _ENGINE_AVAILABLE:
        if not _PRIVILEGED:
            scapy_error = (
                "Run the agent with elevated privileges "
                "(sudo on Linux/macOS, Administrator on Windows)"
            )
        else:
            scapy_error = "Scapy is not installed — run: pip install scapy"

    iface_name = ""
    if _ENGINE_AVAILABLE:
        try:
            from scapy.all import conf as scapy_conf
            iface_name = str(scapy_conf.iface)
        except Exception:
            pass

    from datetime import datetime
    return {
        "status":        "ok",
        "agent":         "local",
        "version":       _AGENT_VER,
        "scapy_live":    _ENGINE_AVAILABLE and _PRIVILEGED,
        "scapy_error":   scapy_error,
        "privileged":    _PRIVILEGED,
        "os":            _OS,
        "default_iface": iface_name,
        "time":          datetime.utcnow().isoformat() + "Z",
    }


@app.get("/setup-info")
def setup_info():
    """Full diagnostic dump — shown in troubleshooting panel."""
    import importlib.metadata

    def _pkg_ver(name: str) -> str:
        try:
            return importlib.metadata.version(name)
        except Exception:
            return "not installed"

    return {
        "python":          sys.version,
        "os":              platform.platform(),
        "privileged":      _PRIVILEGED,
        "packages": {
            "fastapi":  _pkg_ver("fastapi"),
            "uvicorn":  _pkg_ver("uvicorn"),
            "scapy":    _pkg_ver("scapy"),
            "pydantic": _pkg_ver("pydantic"),
        },
        "scapy_available": _ENGINE_AVAILABLE,
        "agent_version":   _AGENT_VER,
    }


class ScanRequest(BaseModel):
    host:    str
    mode:    str   = Field(default="common",  description="common | range | custom")
    timeout: float = Field(default=0.8, ge=0.2, le=5.0)
    start:   int   = Field(default=1,    ge=1, le=65535)
    end:     int   = Field(default=1024, ge=1, le=65535)
    ports:   str   = Field(default="")


@app.post("/scan")
def scan_ports(req: ScanRequest):
    if run_scan is None:
        raise HTTPException(status_code=500, detail="port_scanner_api not found — check your src/ path")
    try:
        return run_scan(
            host=req.host, mode=req.mode, timeout=req.timeout,
            start=req.start, end=req.end, ports=req.ports,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {e}")


@app.get("/traffic/stream")
def traffic_stream(
    duration: int = 15,
    protocol: str = "",
    port:     str = "",
    ip:       str = "",
    src_ip:   str = "",
    dst_ip:   str = "",
    iface:    str = "",
):
    if stream_traffic is None:
        raise HTTPException(status_code=500, detail="traffic_analyzer_api not found — check your src/ path")

    use_real  = _ENGINE_AVAILABLE and _PRIVILEGED
    generator = stream_traffic(
        duration=duration, protocol=protocol,
        port=port, ip=ip, src_ip=src_ip, dst_ip=dst_ip,
        use_real=use_real,
        iface=iface,
    )
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    import uvicorn

    print("\n  SecureKit Local Agent v" + _AGENT_VER)
    print("  " + "─" * 50)
    print(f"  OS:         {platform.system()} {platform.release()}")
    _live_ready = _PRIVILEGED and _ENGINE_AVAILABLE
    print(f"  Privileged: {'YES' if _PRIVILEGED else 'NO'}{' — live capture available' if _live_ready else ' — port scanner only'}")
    print(f"  Scapy:      {'available' if _ENGINE_AVAILABLE else 'not available'}")
    print("  " + "─" * 50)
    print("  Listening on http://127.0.0.1:8765")
    print("  Press Ctrl+C to stop.\n")

    uvicorn.run("local_agent:app", host="127.0.0.1", port=8765, reload=False)