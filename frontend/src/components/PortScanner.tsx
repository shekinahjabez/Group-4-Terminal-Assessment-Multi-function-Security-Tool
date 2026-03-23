import { useState } from "react";
import { Radar, Download } from "lucide-react";
import { useLocalAgent } from "../hooks/useLocalAgent";
import { AgentSetupPanel } from "./AgentSetupPanel";

const API = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

interface PortResult {
  port: number;
  state: "open" | "closed" | "filtered";
  service: string;
  risk: "high" | "medium" | "low" | "info";
}

interface ScanResult {
  host: string;
  ip: string;
  mode: string;
  total_scanned: number;
  open_count: number;
  scan_time: number;
  ports: PortResult[];
}

type ScanMode = "common" | "range" | "custom";

// checks if a host string looks like a private or local ip address
function isPrivateIP(value: string): boolean {
  const h = value.trim();
  return (
    /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h) ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(h) ||
    /^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)
  );
}

const RISK_STYLE: Record<string, { bg: string; border: string; badge_bg: string; badge_text: string }> = {
  high:   { bg: "#fef2f2", border: "#fecaca", badge_bg: "#fee2e2", badge_text: "#b91c1c" },
  medium: { bg: "#fffbeb", border: "#fde68a", badge_bg: "#fef3c7", badge_text: "#92400e" },
  low:    { bg: "#f0fdf4", border: "#bbf7d0", badge_bg: "#dcfce7", badge_text: "#166534" },
  info:   { bg: "#eff6ff", border: "#bfdbfe", badge_bg: "#dbeafe", badge_text: "#1e40af" },
};
const RISK_ICONS: Record<string, string> = { high: "✕", medium: "⚠", low: "✓", info: "i" };

// ── Export helpers ─────────────────────────────────────────────────────────────
// downloads the scan results as a csv file
function exportCSV(result: ScanResult) {
  const rows = [
    ["Port", "State", "Service", "Risk"],
    ...result.ports.map(p => [p.port, p.state, p.service, p.risk]),
  ];
  const csv = [
    `# SecureKit Port Scan — ${result.host} (${result.ip})`,
    `# Mode: ${result.mode} | Scanned: ${result.total_scanned} | Open: ${result.open_count} | Time: ${result.scan_time}s`,
    `# Generated: ${new Date().toISOString()}`,
    "",
    ...rows.map(r => r.join(",")),
  ].join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `portscan_${result.host.replace(/\./g, "_")}_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// downloads the scan results as a json file
function exportJSON(result: ScanResult) {
  const payload = {
    meta: {
      host: result.host, ip: result.ip, mode: result.mode,
      total_scanned: result.total_scanned, open_count: result.open_count,
      scan_time: result.scan_time, generated: new Date().toISOString(),
      tool: "SecureKit — Network Port Scanner",
    },
    ports: result.ports,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `portscan_${result.host.replace(/\./g, "_")}_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// main port scanner component, handles scan config and results display
export function PortScanner() {
  const [host,        setHost]        = useState("");
  const [mode,        setMode]        = useState<ScanMode>("common");
  const [timeout_,    setTimeout_]    = useState(0.8);
  const [startPort,   setStartPort]   = useState(1);
  const [endPort,     setEndPort]     = useState(1024);
  const [customPorts, setCustomPorts] = useState("");
  const [result,      setResult]      = useState<ScanResult | null>(null);
  const [loading,     setLoading]     = useState(false);
  const [error,       setError]       = useState<string | null>(null);
  const [filterRisk,  setFilterRisk]  = useState("all");

  const agent = useLocalAgent();
  const isAgentConnected = agent.state === "running-live" || agent.state === "running-no-scapy";
  const SCAN_BASE = isAgentConnected ? agent.agentUrl : API;
  const SCAN_PATH = isAgentConnected ? "/scan" : "/api/scan";
  const showPrivateIPWarning = !isAgentConnected && isPrivateIP(host);

  // sends the scan request to the agent and stores the results
  const handleScan = async () => {
    if (!host.trim()) { setError("Please enter a target host or IP."); return; }
    if (!isAgentConnected) { setError("Start the local agent to run a port scan."); return; }
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await fetch(`${SCAN_BASE}${SCAN_PATH}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: host.trim(), mode, timeout: timeout_, start: startPort, end: endPort, ports: customPorts.trim() }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data?.detail ?? `Scan failed (${r.status})`);
      setResult(data as ScanResult);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unknown error during scan.");
    } finally {
      setLoading(false);
    }
  };

  const displayed = result
    ? result.ports.filter(p => filterRisk === "all" || p.risk === filterRisk)
    : [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "#1e293b", margin: 0 }}>Network Port Scanner</h2>
        <p style={{ fontSize: 12, color: "#64748b", margin: "4px 0 0" }}>Scan TCP ports and identify running services (Python backend)</p>
      </div>

      {!isAgentConnected && (
        <AgentSetupPanel
          state={agent.state}
          health={agent.health}
          agentUrl={agent.agentUrl}
          toolName="Port Scanner"
          onGrant={agent.grantPermission}
          onReset={agent.resetPermission}
          onRecheck={agent.recheck}
          onSetUrl={agent.setAgentUrl}
        />
      )}

      {/* Config card */}
      <div style={{ backgroundColor: "#f8fafc", border: "2px solid #e2e8f0", borderRadius: 12, padding: 16, display: "flex", flexDirection: "column", gap: 14 }}>

        <div>
          <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#475569", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Target Host / IP</label>
          <input type="text" value={host}
            onChange={e => { setHost(e.target.value); setError(null); }}
            onKeyDown={e => e.key === "Enter" && handleScan()}
            placeholder="e.g. 192.168.1.1 or scanme.nmap.org"
            style={{ width: "100%", padding: "9px 12px", border: "2px solid #e2e8f0", borderRadius: 8, fontSize: 13, color: "#1e293b", backgroundColor: "#fff", outline: "none", boxSizing: "border-box" }}
            onFocus={e => (e.currentTarget.style.borderColor = "#7c3aed")}
            onBlur={e  => (e.currentTarget.style.borderColor = "#e2e8f0")}
          />
          {showPrivateIPWarning && (
            <div style={{ marginTop: 6, backgroundColor: "#fffbeb", border: "1px solid #fcd34d", borderRadius: 6, padding: "6px 10px", fontSize: 10, color: "#92400e", lineHeight: 1.5 }}>
              <strong>Note:</strong> This IP is on a private/LAN range. Without the local agent, the scan runs via the Render cloud backend and will target Render's internal network, not your local machine. Connect the local agent for accurate results.
            </div>
          )}
        </div>

        <div>
          <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#475569", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Scan Mode</label>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
            {(["common", "range", "custom"] as ScanMode[]).map(m => (
              <button key={m} onClick={() => setMode(m)}
                style={{ padding: "8px 0", borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: "pointer", border: mode === m ? "2px solid #7c3aed" : "2px solid #e2e8f0", backgroundColor: mode === m ? "#7c3aed" : "#fff", color: mode === m ? "#fff" : "#64748b", textTransform: "capitalize" }}
              >{m}</button>
            ))}
          </div>
        </div>

        {mode === "range" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[{ label: "Start Port", val: startPort, set: setStartPort }, { label: "End Port", val: endPort, set: setEndPort }].map(({ label, val, set }) => (
              <div key={label}>
                <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#475569", marginBottom: 4 }}>{label}</label>
                <input type="number" min={1} max={65535} value={val} onChange={e => set(Number(e.target.value))}
                  style={{ width: "100%", padding: "8px 10px", border: "2px solid #e2e8f0", borderRadius: 8, fontSize: 13, color: "#1e293b", backgroundColor: "#fff", outline: "none", boxSizing: "border-box" }}
                />
              </div>
            ))}
          </div>
        )}

        {mode === "custom" && (
          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#475569", marginBottom: 4 }}>Port List <span style={{ fontWeight: 400, color: "#94a3b8" }}>(e.g. 80,443,8000-8080)</span></label>
            <input type="text" value={customPorts} onChange={e => setCustomPorts(e.target.value)} placeholder="80,443,22,8000-8080"
              style={{ width: "100%", padding: "8px 10px", border: "2px solid #e2e8f0", borderRadius: 8, fontSize: 13, color: "#1e293b", backgroundColor: "#fff", outline: "none", boxSizing: "border-box" }}
            />
          </div>
        )}

        <div>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em" }}>Timeout per port</label>
            <span style={{ fontSize: 12, fontWeight: 700, color: "#7c3aed" }}>{timeout_.toFixed(1)}s</span>
          </div>
          <input type="range" min={0.2} max={5} step={0.1} value={timeout_} onChange={e => setTimeout_(Number(e.target.value))}
            style={{ width: "100%", accentColor: "#7c3aed", cursor: "pointer" }}
          />
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ fontSize: 10, color: "#94a3b8" }}>0.2s (fast)</span>
            <span style={{ fontSize: 10, color: "#94a3b8" }}>5.0s (thorough)</span>
          </div>
        </div>

        <button onClick={handleScan} disabled={loading || !isAgentConnected}
          title={!isAgentConnected ? "Start the local agent to run a port scan" : undefined}
          style={{ width: "100%", padding: "12px 0", borderRadius: 10, border: "none", cursor: (loading || !isAgentConnected) ? "not-allowed" : "pointer", backgroundColor: (loading || !isAgentConnected) ? "#cbd5e1" : "#7c3aed", color: "#fff", fontWeight: 600, fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, opacity: !isAgentConnected ? 0.6 : 1 }}
          onMouseEnter={e => { if (!loading && isAgentConnected) e.currentTarget.style.backgroundColor = "#6d28d9"; }}
          onMouseLeave={e => { if (!loading && isAgentConnected) e.currentTarget.style.backgroundColor = "#7c3aed"; }}
        >
          {loading
            ? <><span style={{ width: 16, height: 16, border: "2px solid #fff", borderTopColor: "transparent", borderRadius: "50%", display: "inline-block", animation: "spin 0.7s linear infinite" }} />Scanning...</>
            : <><Radar style={{ width: 14, height: 14 }} />Start Scan</>}
        </button>
      </div>

      {error && (
        <div style={{ backgroundColor: "#fef2f2", border: "2px solid #fecaca", borderRadius: 10, padding: "10px 14px", color: "#dc2626", fontSize: 12, display: "flex", gap: 8 }}>
          <span style={{ fontWeight: 700 }}>Error:</span><span>{error}</span>
        </div>
      )}

      {result && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

          {/* Summary */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>
            {[{ label: "Host", value: result.host }, { label: "Scanned", value: String(result.total_scanned) }, { label: "Open", value: String(result.open_count) }, { label: "Time", value: `${result.scan_time.toFixed(1)}s` }].map(s => (
              <div key={s.label} style={{ backgroundColor: "#fff", border: "2px solid #e2e8f0", borderRadius: 10, padding: "10px 12px", textAlign: "center" }}>
                <p style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>{s.label}</p>
                <p style={{ fontSize: 13, fontWeight: 700, color: "#1e293b", margin: "4px 0 0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* Filter + Export row */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["all", "high", "medium", "low", "info"].map(r => (
                <button key={r} onClick={() => setFilterRisk(r)}
                  style={{ padding: "4px 12px", borderRadius: 999, fontSize: 11, fontWeight: 700, cursor: "pointer", border: filterRisk === r ? "2px solid #7c3aed" : "2px solid #e2e8f0", backgroundColor: filterRisk === r ? "#7c3aed" : "#fff", color: filterRisk === r ? "#fff" : "#64748b", textTransform: "capitalize" }}
                >{r === "all" ? `All (${result.ports.length})` : r}</button>
              ))}
            </div>

            {/* Export buttons */}
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={() => exportCSV(result)}
                style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", borderRadius: 8, border: "2px solid #e2e8f0", backgroundColor: "#fff", color: "#475569", fontSize: 12, fontWeight: 600, cursor: "pointer" }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = "#7c3aed")}
                onMouseLeave={e => (e.currentTarget.style.borderColor = "#e2e8f0")}
              >
                <Download style={{ width: 12, height: 12 }} />Export CSV
              </button>
              <button onClick={() => exportJSON(result)}
                style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", borderRadius: 8, border: "2px solid #e2e8f0", backgroundColor: "#fff", color: "#475569", fontSize: 12, fontWeight: 600, cursor: "pointer" }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = "#7c3aed")}
                onMouseLeave={e => (e.currentTarget.style.borderColor = "#e2e8f0")}
              >
                <Download style={{ width: 12, height: 12 }} />Export JSON
              </button>
            </div>
          </div>

          {/* Port list */}
          {displayed.length === 0 ? (
            <div style={{ textAlign: "center", padding: "24px 0", color: "#94a3b8", fontSize: 13 }}>No ports match this filter.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 360, overflowY: "auto" }}>
              {displayed.map(p => {
                const rs = RISK_STYLE[p.risk] ?? RISK_STYLE.info;
                return (
                  <div key={p.port} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 12px", borderRadius: 8, border: `2px solid ${rs.border}`, backgroundColor: rs.bg }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <span style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, color: "#334155", minWidth: 44 }}>{p.port}</span>
                      <span style={{ fontSize: 12, color: "#475569" }}>{p.service || "unknown"}</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ backgroundColor: rs.badge_bg, color: rs.badge_text, borderRadius: 999, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>
                        {RISK_ICONS[p.risk]} {p.risk}
                      </span>
                      <span style={{ fontSize: 11, fontWeight: 600, color: p.state === "open" ? "#16a34a" : "#94a3b8", textTransform: "capitalize" }}>{p.state}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {!result && !loading && !error && (
        <div style={{ backgroundColor: "#f5f3ff", border: "2px solid #ddd6fe", borderRadius: 12, padding: 24, textAlign: "center" }}>
          <Radar style={{ width: 32, height: 32, color: "#7c3aed", marginBottom: 8 }} />
          <p style={{ fontSize: 14, fontWeight: 600, color: "#4c1d95", margin: "0 0 4px" }}>Ready to scan</p>
          <p style={{ fontSize: 12, color: "#7c3aed", margin: 0 }}>Enter a host and press Start Scan</p>
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}