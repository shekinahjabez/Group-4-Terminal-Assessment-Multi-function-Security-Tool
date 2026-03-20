"""
api.py — SecureKit FastAPI backend
Milestone 1: password generation, assessment, input validation
Milestone 2: port scanning, traffic analysis (SSE stream)
"""

import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# ── Path setup ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR  = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# ── MS1 imports (unchanged) ───────────────────────────────────────────────────
from web_security_tool.password_generator import ProcessGenerator
from web_security_tool.password_assessor  import PasswordAssessor
from web_security_tool.input_validator    import InputValidator

# ── MS2 imports ───────────────────────────────────────────────────────────────
from web_security_tool.port_scanner_api     import run_scan
from web_security_tool.traffic_analyzer_api import stream_traffic, snapshot_traffic

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureKit — Multi-Function Security Tool",
    description="Terminal Assessment · MO-IT142 Security Script Programming",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Production frontend
        "https://group-4-terminal-assessment-multi.onrender.com",
        # TA frontend
        "https://securekit.onrender.com",
        # Local dev
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", include_in_schema=False)
@app.api_route("/api", methods=["GET", "HEAD"], include_in_schema=False)
def root():
    return {
        "status":  "ok",
        "service": "SecureKit Backend v2.0",
        "modules": [
            "POST /api/generate   — Password generator",
            "POST /api/assess     — Password strength assessor",
            "POST /api/validate   — Input validator & sanitizer",
            "POST /api/scan       — Network port scanner",
            "GET  /api/traffic/stream   — Live traffic (SSE)",
            "POST /api/traffic/snapshot — Traffic snapshot",
        ],
    }

@app.get("/health")
def health():
    from datetime import datetime
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


# ══════════════════════════════════════════════════════════════════════════════
#  MS1 — PASSWORD GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=4, le=128)

@app.post("/api/generate")
def generate_password(req: GenerateRequest):
    pwd, sha, bcr, ts = ProcessGenerator.generate(req.length)
    return {"password": pwd, "sha256": sha, "bcrypt": bcr, "timestamp": ts}


# ══════════════════════════════════════════════════════════════════════════════
#  MS1 — PASSWORD ASSESSOR
# ══════════════════════════════════════════════════════════════════════════════

class AssessRequest(BaseModel):
    password: str

@app.post("/api/assess")
def assess_password(req: AssessRequest):
    result = PasswordAssessor.evaluate_password(req.password)
    return {"result": result}


# ══════════════════════════════════════════════════════════════════════════════
#  MS1 — INPUT VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

class ValidateRequest(BaseModel):
    field_type: str = Field(..., description="name | email | username | message")
    value: str

@app.post("/api/validate")
def validate_input(req: ValidateRequest):
    ft = (req.field_type or "").lower().strip()
    sanitized, was_sanitized, notes = InputValidator.sanitize_input(req.value, ft)

    sql_detected    = any("SQL keyword/pattern detected" in n for n in notes)
    validation_text = req.value if sql_detected else sanitized

    if ft in ("name", "full_name", "fullname"):
        is_valid, errors = InputValidator.validate_full_name(validation_text)
        ft_out = "name"
    elif ft == "email":
        is_valid, errors = InputValidator.validate_email_simple(validation_text)
        ft_out = "email"
    elif ft == "username":
        is_valid, errors = InputValidator.validate_username(validation_text)
        ft_out = "username"
    elif ft == "message":
        is_valid, errors = InputValidator.validate_message(validation_text)
        ft_out = "message"
    else:
        raise HTTPException(
            status_code=400,
            detail="Unknown field_type. Use: name, email, username, message",
        )

    sanitized_out = "[BLOCKED: SQL detected]" if sql_detected else sanitized
    return {
        "field_type":    ft_out,
        "original":      req.value,
        "sanitized":     sanitized_out,
        "was_sanitized": was_sanitized,
        "notes":         notes,
        "is_valid":      is_valid,
        "errors":        errors,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MS2 — PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    host:    str
    mode:    str   = Field(default="common", description="common | range | custom")
    timeout: float = Field(default=0.8, ge=0.2, le=5.0)
    start:   int   = Field(default=1,    ge=1,   le=65535)
    end:     int   = Field(default=1024, ge=1,   le=65535)
    ports:   str   = Field(default="",  description="Custom port list e.g. 80,443,8000-8080")

@app.post("/api/scan")
def scan_ports(req: ScanRequest):
    """
    Run a TCP port scan using MS2's ScanEngine / scan_port() logic.
    Returns resolved IP, open ports with service names and risk levels.
    """
    try:
        result = run_scan(
            host    = req.host,
            mode    = req.mode,
            timeout = req.timeout,
            start   = req.start,
            end     = req.end,
            ports   = req.ports,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  MS2 — TRAFFIC ANALYZER (SSE stream + snapshot)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/traffic/stream")
def traffic_stream(
    duration: int = 15,
    protocol: str = "",
    port:     str = "",
    ip:       str = "",
    src_ip:   str = "",
    dst_ip:   str = "",
):
    """
    Server-Sent Events stream of captured/simulated packets.
    Uses MS2's CaptureEngine (scapy AsyncSniffer) when root is available;
    falls back to realistic simulation on Render / non-root environments.

    Query params mirror MS2's CLI filter options:
      protocol — tcp | udp | icmp | (empty = all)
      port     — port number to filter
      ip       — match src OR dst host
      src_ip   — match source host only
      dst_ip   — match destination host only
    """
    generator = stream_traffic(
        duration = duration,
        protocol = protocol,
        port     = port,
        ip       = ip,
        src_ip   = src_ip,
        dst_ip   = dst_ip,
    )
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",     # disable Nginx buffering on Render
        },
    )


class SnapshotRequest(BaseModel):
    count: int = Field(default=20, ge=1, le=50)

@app.post("/api/traffic/snapshot")
def traffic_snapshot(req: SnapshotRequest):
    """Single-shot packet snapshot — non-streaming, always simulated."""
    return snapshot_traffic(req.count)