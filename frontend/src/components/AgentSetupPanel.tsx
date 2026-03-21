/**
 * AgentSetupPanel
 *
 * Renders contextual UI for every non-operational agent state:
 *   permission-pending  → consent prompt
 *   permission-denied   → simulation notice + "change" link
 *   checking            → spinner
 *   not-running         → install + start instructions (OS-aware)
 *   running-no-scapy    → partial capability notice (scanner only)
 */
import { Terminal, RefreshCw, ChevronRight } from "lucide-react";
import type { AgentState, AgentHealthPayload } from "../hooks/useLocalAgent";

interface Props {
  state:      AgentState;
  health:     AgentHealthPayload | null;
  toolName:   "Port Scanner" | "Traffic Analyzer";
  onGrant:    () => void;
  onDeny:     () => void;
  onReset:    () => void;
  onRecheck:  () => void;
}

function StartCommand({ os }: { os: string }) {
  const isWin = os === "windows";
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {!isWin && (
        <div>
          <p style={{ fontSize: 10, color: "#64748b", margin: "0 0 4px" }}>
            With live traffic capture (requires sudo):
          </p>
          <code style={{ display: "block", backgroundColor: "#0f172a", color: "#34d399", fontSize: 11, padding: "8px 12px", borderRadius: 8, fontFamily: "monospace" }}>
            sudo python local_agent.py
          </code>
        </div>
      )}
      <div>
        <p style={{ fontSize: 10, color: "#64748b", margin: "0 0 4px" }}>
          {isWin ? "Run in an Administrator terminal:" : "Port scanner only (no sudo needed):"}
        </p>
        <code style={{ display: "block", backgroundColor: "#0f172a", color: "#34d399", fontSize: 11, padding: "8px 12px", borderRadius: 8, fontFamily: "monospace" }}>
          python local_agent.py
        </code>
      </div>
    </div>
  );
}

export function AgentSetupPanel({ state, health, toolName, onGrant, onDeny, onReset, onRecheck }: Props) {

  // ── Permission pending ────────────────────────────────────────────────────
  if (state === "permission-pending") {
    return (
      <div style={{ backgroundColor: "#eef2ff", border: "2px solid #c7d2fe", borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", gap: 16 }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, backgroundColor: "#4f46e5", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
            <Terminal style={{ width: 18, height: 18, color: "#fff" }} />
          </div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 700, color: "#1e1b4b", margin: "0 0 4px" }}>
              Enable Local Network Scanning?
            </p>
            <p style={{ fontSize: 11, color: "#3730a3", margin: "0 0 8px", lineHeight: 1.5 }}>
              The <strong>{toolName}</strong> can run directly on your machine using a lightweight local agent (<code style={{ fontFamily: "monospace", backgroundColor: "#c7d2fe", padding: "1px 4px", borderRadius: 3 }}>local_agent.py</code>). This allows real TCP port scanning and live packet capture on your local network.
            </p>
            <p style={{ fontSize: 11, color: "#4338ca", margin: 0, lineHeight: 1.5 }}>
              The app will connect to{" "}
              <code style={{ fontFamily: "monospace", backgroundColor: "#c7d2fe", padding: "1px 4px", borderRadius: 3 }}>http://127.0.0.1:8765</code>{" "}
              on your machine. <strong>Nothing is sent to any external server.</strong>
            </p>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          <button
            onClick={onGrant}
            style={{ backgroundColor: "#4f46e5", color: "#fff", border: "none", borderRadius: 10, padding: "10px 16px", fontWeight: 600, fontSize: 12, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}
            onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#4338ca")}
            onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#4f46e5")}
          >
            <Terminal style={{ width: 14, height: 14 }} />
            Enable Local Scanning
          </button>
          <button
            onClick={onDeny}
            style={{ backgroundColor: "#fff", border: "2px solid #c7d2fe", borderRadius: 10, padding: "10px 16px", fontWeight: 600, fontSize: 12, color: "#4338ca", cursor: "pointer" }}
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
        <button
          onClick={onReset}
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
      <div style={{ backgroundColor: "#f8fafc", border: "2px solid #e2e8f0", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ width: 16, height: 16, border: "2px solid #818cf8", borderTopColor: "transparent", borderRadius: "50%", display: "inline-block", animation: "spin 0.8s linear infinite", flexShrink: 0 }} />
        <p style={{ fontSize: 11, color: "#64748b", margin: 0 }}>
          Checking for local agent at{" "}
          <code style={{ fontFamily: "monospace", color: "#334155" }}>127.0.0.1:8765</code>…
        </p>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  // ── Not running ───────────────────────────────────────────────────────────
  if (state === "not-running") {
    const os = health?.os ?? "windows";
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
                No response at <code style={{ fontFamily: "monospace", backgroundColor: "#fde68a", padding: "1px 4px", borderRadius: 3 }}>127.0.0.1:8765</code>. Follow the steps below.
              </p>
            </div>
          </div>
          <button
            onClick={onRecheck}
            title="Check again"
            style={{ width: 28, height: 28, borderRadius: 8, backgroundColor: "#fef3c7", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}
            onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#fde68a")}
            onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#fef3c7")}
          >
            <RefreshCw style={{ width: 14, height: 14, color: "#92400e" }} />
          </button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {/* Step 1 */}
          <div style={{ display: "flex", gap: 12 }}>
            <div style={{ width: 20, height: 20, borderRadius: "50%", backgroundColor: "#fcd34d", color: "#78350f", fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 2 }}>1</div>
            <div style={{ flex: 1 }}>
              <p style={{ fontSize: 11, fontWeight: 600, color: "#78350f", margin: "0 0 4px" }}>Verify your environment</p>
              <p style={{ fontSize: 10, color: "#92400e", margin: "0 0 6px", lineHeight: 1.5 }}>Run the one-shot checker from the repo root. It will tell you what is missing and can auto-install packages.</p>
              <code style={{ display: "block", backgroundColor: "#0f172a", color: "#34d399", fontSize: 11, padding: "8px 12px", borderRadius: 8, fontFamily: "monospace" }}>
                python setup_check.py --install
              </code>
            </div>
          </div>
          {/* Step 2 */}
          <div style={{ display: "flex", gap: 12 }}>
            <div style={{ width: 20, height: 20, borderRadius: "50%", backgroundColor: "#fcd34d", color: "#78350f", fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 2 }}>2</div>
            <div style={{ flex: 1 }}>
              <p style={{ fontSize: 11, fontWeight: 600, color: "#78350f", margin: "0 0 4px" }}>Start the local agent</p>
              <p style={{ fontSize: 10, color: "#92400e", margin: "0 0 6px", lineHeight: 1.5 }}>Run from the repo root. Keep this terminal open while using the tool.</p>
              <StartCommand os={os} />
            </div>
          </div>
          {/* Step 3 */}
          <div style={{ display: "flex", gap: 12 }}>
            <div style={{ width: 20, height: 20, borderRadius: "50%", backgroundColor: "#fcd34d", color: "#78350f", fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: 2 }}>3</div>
            <div style={{ flex: 1 }}>
              <p style={{ fontSize: 11, fontWeight: 600, color: "#78350f", margin: "0 0 2px" }}>Click "Check Again" once the agent is running</p>
              <p style={{ fontSize: 10, color: "#92400e", margin: 0 }}>The agent prints "Listening on http://127.0.0.1:8765" when ready.</p>
            </div>
          </div>
        </div>

        <div style={{ borderTop: "1px solid #fcd34d", paddingTop: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <p style={{ fontSize: 10, color: "#92400e", margin: 0 }}>Don't want to install the agent?</p>
          <button
            onClick={onDeny}
            style={{ fontSize: 10, color: "#78350f", background: "none", border: "none", cursor: "pointer", fontWeight: 600, textDecoration: "underline", display: "flex", alignItems: "center", gap: 4 }}
            onMouseEnter={e => (e.currentTarget.style.color = "#451a03")}
            onMouseLeave={e => (e.currentTarget.style.color = "#78350f")}
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
      <div style={{ backgroundColor: "#f0f9ff", border: "2px solid #bae6fd", borderRadius: 10, padding: 14, display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#38bdf8", flexShrink: 0, marginTop: 4 }} />
          <div style={{ flex: 1 }}>
            <p style={{ fontSize: 11, fontWeight: 600, color: "#0c4a6e", margin: "0 0 2px" }}>
              Local Agent Connected — {isPrivilegeIssue ? "Limited Mode" : "Scapy Unavailable"}
            </p>
            <p style={{ fontSize: 10, color: "#0369a1", margin: 0 }}>{reason}</p>
          </div>
          <button
            onClick={onRecheck}
            title="Recheck"
            style={{ width: 24, height: 24, borderRadius: 6, backgroundColor: "#e0f2fe", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}
          >
            <RefreshCw style={{ width: 12, height: 12, color: "#0369a1" }} />
          </button>
        </div>
        {isPrivilegeIssue && (
          <div style={{ marginLeft: 18, paddingLeft: 10, borderLeft: "2px solid #bae6fd" }}>
            <p style={{ fontSize: 10, color: "#0369a1", margin: "0 0 4px" }}>To enable live capture, restart with:</p>
            <code style={{ display: "block", backgroundColor: "#0f172a", color: "#34d399", fontSize: 10, padding: "6px 10px", borderRadius: 6, fontFamily: "monospace" }}>
              {health?.os === "windows" ? "python local_agent.py  (Administrator terminal)" : "sudo python local_agent.py"}
            </code>
          </div>
        )}
      </div>
    );
  }

  // "running-live" → parent renders the tool normally, nothing shown here
  return null;
}