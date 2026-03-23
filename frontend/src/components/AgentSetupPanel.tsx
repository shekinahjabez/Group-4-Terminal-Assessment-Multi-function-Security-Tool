/**
 * AgentSetupPanel
 *
 * Includes download buttons for local_agent.py, setup scripts,
 * and a URL input so users can paste their ngrok URL — no CLI or
 * code changes needed.
 */
import { useState } from "react";
import { Terminal, RefreshCw, ChevronRight, Link, Download, Monitor } from "lucide-react";
import type { AgentState, AgentHealthPayload } from "../hooks/useLocalAgent";
import { DEFAULT_AGENT_URL } from "../hooks/useLocalAgent";

interface Props {
  state:      AgentState;
  health:     AgentHealthPayload | null;
  agentUrl:   string;
  toolName:   "Port Scanner" | "Traffic Analyzer";
  onGrant:    () => void;
  onDeny:     () => void;
  onReset:    () => void;
  onRecheck:  (url?: string) => void;
  onSetUrl:   (url: string) => void;
}

// ── File download links — point to your Render static files or GitHub raw ────
const GITHUB_RAW = "https://raw.githubusercontent.com/shekinahjabez/Group-4-Terminal-Assessment-Multi-function-Security-Tool/main";

const DOWNLOADS = {
  agent:   { label: "local_agent.py",           url: `${GITHUB_RAW}/local_agent.py` },
  check:   { label: "setup_check.py",           url: `${GITHUB_RAW}/setup_check.py` },
  windows: { label: "StartAgent.bat",  url: `${GITHUB_RAW}/StartAgent.bat` },
  mac:     { label: "StartAgent.sh", url: `${GITHUB_RAW}/StartAgent.sh` },
};

// ── Download button ───────────────────────────────────────────────────────────
function DlBtn({ label, url, accent = "#4f46e5" }: { label: string; url: string; accent?: string }) {
  const [status, setStatus] = useState<"idle" | "loading" | "error">("idle");

  const handleDownload = async () => {
    setStatus("loading");
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = label;
      a.click();
      URL.revokeObjectURL(a.href);
      setStatus("idle");
    } catch {
      setStatus("error");
      setTimeout(() => setStatus("idle"), 3000);
    }
  };

  const isLoading = status === "loading";
  const isError   = status === "error";

  return (
    <button onClick={handleDownload} disabled={isLoading}
      style={{ display: "flex", alignItems: "center", gap: 6, padding: "7px 12px", backgroundColor: isError ? "#fef2f2" : "#fff", border: `2px solid ${isError ? "#fca5a5" : accent + "22"}`, borderRadius: 8, fontSize: 11, fontWeight: 600, color: isError ? "#dc2626" : accent, cursor: isLoading ? "not-allowed" : "pointer", opacity: isLoading ? 0.7 : 1 }}
      onMouseEnter={e => { if (!isLoading && !isError) e.currentTarget.style.backgroundColor = `${accent}11`; }}
      onMouseLeave={e => { if (!isError) e.currentTarget.style.backgroundColor = "#fff"; }}
    >
      <Download style={{ width: 12, height: 12 }} />
      {isLoading ? "Downloading…" : isError ? "Download failed" : label}
    </button>
  );
}

// ── Download panel ────────────────────────────────────────────────────────────
function DownloadPanel() {
  return (
    <div style={{ backgroundColor: "#faf5ff", border: "2px solid #e9d5ff", borderRadius: 10, padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Monitor style={{ width: 14, height: 14, color: "#7c3aed" }} />
        <p style={{ fontSize: 11, fontWeight: 700, color: "#4c1d95", margin: 0 }}>Step 1 — Download & Run on Your Machine</p>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {/* Windows */}
        <div style={{ backgroundColor: "#fff", border: "1px solid #e9d5ff", borderRadius: 8, padding: 10 }}>
          <p style={{ fontSize: 10, fontWeight: 700, color: "#6d28d9", margin: "0 0 6px", textTransform: "uppercase" as const, letterSpacing: "0.05em" }}>
            🪟 Windows
          </p>
          <p style={{ fontSize: 10, color: "#7c3aed", margin: "0 0 8px", lineHeight: 1.5 }}>
            Download all files below into the <strong>same folder</strong>, then double-click <code style={{ fontFamily: "monospace", backgroundColor: "#ede9fe", padding: "1px 4px", borderRadius: 3 }}>StartAgent.bat</code> — it creates a virtualenv, installs dependencies, and starts the agent. Open Chrome or Edge and visit <code style={{ fontFamily: "monospace", backgroundColor: "#ede9fe", padding: "1px 4px", borderRadius: 3 }}>https://securekit.onrender.com</code> or <code style={{ fontFamily: "monospace", backgroundColor: "#ede9fe", padding: "1px 4px", borderRadius: 3 }}>http://localhost:5173</code>.
          </p>
          <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 6 }}>
            <DlBtn label="StartAgent.bat" url={DOWNLOADS.windows.url} accent="#7c3aed" />
            <DlBtn label="local_agent.py"           url={DOWNLOADS.agent.url}   accent="#7c3aed" />
            <DlBtn label="setup_check.py"           url={DOWNLOADS.check.url}   accent="#7c3aed" />
          </div>
        </div>

        {/* Mac / Linux */}
        <div style={{ backgroundColor: "#fff", border: "1px solid #e9d5ff", borderRadius: 8, padding: 10 }}>
          <p style={{ fontSize: 10, fontWeight: 700, color: "#6d28d9", margin: "0 0 6px", textTransform: "uppercase" as const, letterSpacing: "0.05em" }}>
            Mac / Linux
          </p>
          <p style={{ fontSize: 10, color: "#7c3aed", margin: "0 0 8px", lineHeight: 1.5 }}>
            Download all files into the same folder, open Terminal in that folder, then run:
            <code style={{ display: "block", marginTop: 4, backgroundColor: "#0f172a", color: "#34d399", fontSize: 10, padding: "6px 10px", borderRadius: 6, fontFamily: "monospace" }}>
              chmod +x StartAgent.sh && ./StartAgent.sh
            </code>
          </p>
          <div style={{ display: "flex", flexWrap: "wrap" as const, gap: 6 }}>
            <DlBtn label="StartAgent.sh" url={DOWNLOADS.mac.url}   accent="#7c3aed" />
            <DlBtn label="local_agent.py"            url={DOWNLOADS.agent.url} accent="#7c3aed" />
            <DlBtn label="setup_check.py"            url={DOWNLOADS.check.url} accent="#7c3aed" />
          </div>
        </div>
      </div>

      <p style={{ fontSize: 10, color: "#7c3aed", margin: 0, lineHeight: 1.5 }}>
        Once the script is running, the agent listens at <code style={{ fontFamily: "monospace", backgroundColor: "#ede9fe", padding: "1px 4px", borderRadius: 3 }}>http://127.0.0.1:8765</code> — no ngrok required. Use Chrome or Edge for the hosted site (Firefox blocks local connections from HTTPS pages).
      </p>
    </div>
  );
}

// ── URL configurator ──────────────────────────────────────────────────────────
function AgentUrlInput({ agentUrl, onSetUrl, onRecheck }: {
  agentUrl:  string;
  onSetUrl:  (url: string) => void;
  onRecheck:  (url?: string) => void;
}) {
  const [input, setInput] = useState(agentUrl);
  const isNgrok   = input.includes("ngrok") || (input.startsWith("https://") && !input.includes("127.0.0.1"));
  const isDefault = input === DEFAULT_AGENT_URL || input === "";

  const handleConnect = () => {
    const clean = input.trim().replace(/\/+$/, "");
    if (!clean) return;
    onSetUrl(clean);
    onRecheck(clean);  // pass URL directly instead of setTimeout
  };

  return (
    <div style={{ backgroundColor: "#f0fdf4", border: "2px solid #bbf7d0", borderRadius: 10, padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Link style={{ width: 14, height: 14, color: "#16a34a", flexShrink: 0 }} />
        <p style={{ fontSize: 11, fontWeight: 700, color: "#14532d", margin: 0 }}>
          Step 2 — Paste Your Agent URL
        </p>
        {isNgrok && (
          <span style={{ fontSize: 9, backgroundColor: "#dcfce7", color: "#15803d", border: "1px solid #86efac", borderRadius: 999, padding: "2px 8px", fontWeight: 700 }}>
            NGROK DETECTED
          </span>
        )}
      </div>

      <div style={{ display: "flex", gap: 6 }}>
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleConnect()}
          placeholder="https://abc123.ngrok-free.app  (or http://127.0.0.1:8765 for local)"
          style={{ flex: 1, padding: "8px 10px", border: "2px solid #bbf7d0", borderRadius: 8, fontSize: 11, color: "#134e4a", backgroundColor: "#fff", outline: "none", fontFamily: "monospace" }}
        />
        <button onClick={handleConnect}
          style={{ backgroundColor: "#16a34a", color: "#fff", border: "none", borderRadius: 8, padding: "8px 16px", fontSize: 12, fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap" }}
          onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#15803d")}
          onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#16a34a")}
        >
          Connect
        </button>
        {!isDefault && (
          <button
            onClick={() => { setInput(DEFAULT_AGENT_URL); onSetUrl(DEFAULT_AGENT_URL); onRecheck(DEFAULT_AGENT_URL); }}
            title="Reset to localhost"
            style={{ backgroundColor: "#fff", color: "#64748b", border: "2px solid #bbf7d0", borderRadius: 8, padding: "8px 10px", fontSize: 10, cursor: "pointer" }}
          >
            Reset
          </button>
        )}
      </div>

      <p style={{ fontSize: 10, color: "#166534", margin: 0, lineHeight: 1.5 }}>
        The default URL <code style={{ fontFamily: "monospace", backgroundColor: "#dcfce7", padding: "1px 4px", borderRadius: 3 }}>http://127.0.0.1:8765</code> works for Chrome and Edge on the same machine. For multi-device access, paste your ngrok forwarding URL (e.g. <code style={{ fontFamily: "monospace", backgroundColor: "#dcfce7", padding: "1px 4px", borderRadius: 3 }}>https://abc123.ngrok-free.app</code>) and click <strong>Connect</strong>.
      </p>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────
export function AgentSetupPanel({ state, health, agentUrl, toolName, onGrant, onDeny, onReset, onRecheck, onSetUrl }: Props) {

  // ── Permission pending ────────────────────────────────────────────────────
  if (state === "permission-pending") {
    return (
      <div style={{ backgroundColor: "#eef2ff", border: "2px solid #c7d2fe", borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, backgroundColor: "#4f46e5", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
            <Terminal style={{ width: 18, height: 18, color: "#fff" }} />
          </div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 700, color: "#1e1b4b", margin: "0 0 4px" }}>Enable Local Network Scanning?</p>
            <p style={{ fontSize: 11, color: "#3730a3", margin: 0, lineHeight: 1.5 }}>
              The <strong>{toolName}</strong> can capture real packets from your machine's network interface. Follow the steps below — no command line experience needed.
            </p>
          </div>
        </div>

        <DownloadPanel />
        <AgentUrlInput agentUrl={agentUrl} onSetUrl={onSetUrl} onRecheck={onRecheck} />

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          <button onClick={onGrant}
            style={{ backgroundColor: "#4f46e5", color: "#fff", border: "none", borderRadius: 10, padding: "11px 16px", fontWeight: 600, fontSize: 12, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}
            onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#4338ca")}
            onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#4f46e5")}
          >
            <Terminal style={{ width: 14, height: 14 }} />
            Enable Local Scanning
          </button>
          <button onClick={onDeny}
            style={{ backgroundColor: "#fff", border: "2px solid #c7d2fe", borderRadius: 10, padding: "11px 16px", fontWeight: 600, fontSize: 12, color: "#4338ca", cursor: "pointer" }}
            onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#eef2ff")}
            onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#fff")}
          >
            Use Simulation Instead
          </button>
        </div>
      </div>
    );
  }

  // ── Permission denied ─────────────────────────────────────────────────────
  if (state === "permission-denied") {
    return (
      <div style={{ backgroundColor: "#f8fafc", border: "2px solid #e2e8f0", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
        <div>
          <p style={{ fontSize: 12, fontWeight: 600, color: "#475569", margin: "0 0 2px" }}>Using simulation mode</p>
          <p style={{ fontSize: 10, color: "#94a3b8", margin: 0 }}>{toolName} is running in demonstration mode with simulated data.</p>
        </div>
        <button onClick={onReset}
          style={{ fontSize: 10, color: "#64748b", background: "none", border: "none", cursor: "pointer", textDecoration: "underline", whiteSpace: "nowrap", fontWeight: 600 }}
          onMouseEnter={e => (e.currentTarget.style.color = "#4f46e5")}
          onMouseLeave={e => (e.currentTarget.style.color = "#64748b")}
        >
          Change
        </button>
      </div>
    );
  }

  // ── Checking ──────────────────────────────────────────────────────────────
  if (state === "checking") {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <div style={{ backgroundColor: "#f8fafc", border: "2px solid #e2e8f0", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 16, height: 16, border: "2px solid #818cf8", borderTopColor: "transparent", borderRadius: "50%", display: "inline-block", animation: "spin 0.8s linear infinite", flexShrink: 0 }} />
          <p style={{ fontSize: 11, color: "#64748b", margin: 0 }}>
            Connecting to <code style={{ fontFamily: "monospace", color: "#334155" }}>{agentUrl}</code>…
          </p>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
        <AgentUrlInput agentUrl={agentUrl} onSetUrl={onSetUrl} onRecheck={onRecheck} />
      </div>
    );
  }

  // ── Not running ───────────────────────────────────────────────────────────
  if (state === "not-running") {
    return (
      <div style={{ backgroundColor: "#fffbeb", border: "2px solid #fcd34d", borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, backgroundColor: "#f59e0b", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <Terminal style={{ width: 16, height: 16, color: "#fff" }} />
            </div>
            <div>
              <p style={{ fontSize: 13, fontWeight: 700, color: "#78350f", margin: "0 0 2px" }}>Local Agent Not Detected</p>
              <p style={{ fontSize: 11, color: "#92400e", margin: 0 }}>
                No response at <code style={{ fontFamily: "monospace", backgroundColor: "#fde68a", padding: "1px 4px", borderRadius: 3 }}>{agentUrl}</code>
              </p>
            </div>
          </div>
          <button onClick={() => onRecheck()} title="Check again"
            style={{ width: 28, height: 28, borderRadius: 8, backgroundColor: "#fef3c7", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}
            onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#fde68a")}
            onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#fef3c7")}
          >
            <RefreshCw style={{ width: 14, height: 14, color: "#92400e" }} />
          </button>
        </div>

        {/* Browser compatibility note */}
        <div style={{ backgroundColor: "#fef9c3", border: "1px solid #fde68a", borderRadius: 8, padding: "10px 12px" }}>
          <p style={{ fontSize: 11, fontWeight: 600, color: "#713f12", margin: "0 0 2px" }}>
            Browser requirement: Chrome or Edge
          </p>
          <p style={{ fontSize: 10, color: "#92400e", margin: 0, lineHeight: 1.5 }}>
            Live agent features require <strong>Chrome</strong> or <strong>Edge</strong> when using the hosted site at{" "}
            <code style={{ fontFamily: "monospace", backgroundColor: "#fde68a", padding: "1px 3px", borderRadius: 2 }}>securekit.onrender.com</code>.
            Firefox blocks local connections from HTTPS pages.
            The <strong>Snapshot</strong> button works in all browsers without the agent.
          </p>
        </div>

        <DownloadPanel />
        <AgentUrlInput agentUrl={agentUrl} onSetUrl={onSetUrl} onRecheck={onRecheck} />

        <div style={{ borderTop: "1px solid #fcd34d", paddingTop: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <p style={{ fontSize: 10, color: "#92400e", margin: 0 }}>Don't want to install the agent?</p>
          <button onClick={onDeny}
            style={{ fontSize: 10, color: "#78350f", background: "none", border: "none", cursor: "pointer", fontWeight: 600, textDecoration: "underline", display: "flex", alignItems: "center", gap: 4 }}
          >
            Use simulation instead <ChevronRight style={{ width: 12, height: 12 }} />
          </button>
        </div>
      </div>
    );
  }

  // ── Running but no Scapy ──────────────────────────────────────────────────
  if (state === "running-no-scapy") {
    const reason = health?.scapy_error ?? "Run the agent with elevated privileges for live capture.";
    const isPrivilegeIssue = reason.toLowerCase().includes("privilege") ||
                             reason.toLowerCase().includes("root") ||
                             reason.toLowerCase().includes("administrator");
    return (
      <div style={{ backgroundColor: "#f0f9ff", border: "2px solid #bae6fd", borderRadius: 10, padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#38bdf8", flexShrink: 0, marginTop: 4 }} />
          <div style={{ flex: 1 }}>
            <p style={{ fontSize: 11, fontWeight: 600, color: "#0c4a6e", margin: "0 0 2px" }}>
              Local Agent Connected — {isPrivilegeIssue ? "Limited Mode" : "Scapy Unavailable"}
            </p>
            <p style={{ fontSize: 10, color: "#0369a1", margin: 0 }}>{reason}</p>
          </div>
          <button onClick={() => onRecheck()} title="Recheck"
            style={{ width: 24, height: 24, borderRadius: 6, backgroundColor: "#e0f2fe", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}
          >
            <RefreshCw style={{ width: 12, height: 12, color: "#0369a1" }} />
          </button>
        </div>
        {isPrivilegeIssue && (
          <div style={{ marginLeft: 18, paddingLeft: 10, borderLeft: "2px solid #bae6fd" }}>
            <p style={{ fontSize: 10, color: "#0369a1", margin: "0 0 4px" }}>Re-run the setup script as Administrator for live capture.</p>
          </div>
        )}
        <AgentUrlInput agentUrl={agentUrl} onSetUrl={onSetUrl} onRecheck={onRecheck} />
      </div>
    );
  }

  return null;
}