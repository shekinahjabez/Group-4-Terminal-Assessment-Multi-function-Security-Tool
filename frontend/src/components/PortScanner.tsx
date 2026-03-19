import { useState } from "react";
import { Radar, Play, X, AlertTriangle, CheckCircle2, XCircle, Info } from "lucide-react";

const API = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

// ── Types ─────────────────────────────────────────────────────────────────────
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

const RISK_META = {
  high:   { color: "text-red-700",    bg: "bg-red-50 border-red-200",    badge: "bg-red-100 text-red-700",    icon: <XCircle      className="w-3 h-3" /> },
  medium: { color: "text-amber-700",  bg: "bg-amber-50 border-amber-200",badge: "bg-amber-100 text-amber-700",icon: <AlertTriangle className="w-3 h-3" /> },
  low:    { color: "text-emerald-700",bg: "bg-emerald-50 border-emerald-200",badge: "bg-emerald-100 text-emerald-700",icon: <CheckCircle2 className="w-3 h-3" /> },
  info:   { color: "text-blue-700",   bg: "bg-blue-50 border-blue-200",  badge: "bg-blue-100 text-blue-700",  icon: <Info          className="w-3 h-3" /> },
};

// ── Component ─────────────────────────────────────────────────────────────────
export function PortScanner() {
  const [host, setHost]           = useState("");
  const [mode, setMode]           = useState<ScanMode>("common");
  const [timeout, setTimeout_]    = useState(0.8);
  const [startPort, setStartPort] = useState(1);
  const [endPort, setEndPort]     = useState(1024);
  const [customPorts, setCustomPorts] = useState("");

  const [result,  setResult]  = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  const [filterRisk, setFilterRisk] = useState<string>("all");

  const handleScan = async () => {
    if (!host.trim()) { setError("Please enter a target host or IP."); return; }
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      if (!API) throw new Error("VITE_API_BASE_URL is not set.");

      const body: Record<string, unknown> = {
        host:    host.trim(),
        mode,
        timeout,
        start:   startPort,
        end:     endPort,
        ports:   customPorts.trim(),
      };

      const r = await fetch(`${API}/api/scan`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
      });

      const ct = r.headers.get("content-type") || "";
      if (!ct.includes("application/json")) {
        const text = await r.text();
        throw new Error(`Server returned ${r.status} (non-JSON): ${text.slice(0, 120)}`);
      }

      const data = await r.json();
      if (!r.ok) throw new Error(data?.detail ?? `Scan failed (${r.status})`);

      setResult(data as ScanResult);
    } catch (err: any) {
      setError(err?.message ?? "Unknown error during scan.");
    } finally {
      setLoading(false);
    }
  };

  const displayed = result
    ? result.ports.filter(p =>
        filterRisk === "all" ? true : p.risk === filterRisk
      )
    : [];

  return (
    <div className="space-y-4 h-full overflow-y-auto pr-1">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-800 mb-0.5">Network Port Scanner</h2>
        <p className="text-slate-600 text-xs">Scan TCP ports and identify running services (Python backend)</p>
      </div>

      {/* Config Card */}
      <div className="bg-slate-50 border-2 border-slate-200 rounded-xl p-4 space-y-3">

        {/* Host */}
        <div>
          <label className="block text-xs font-semibold text-slate-700 mb-1">Target Host / IP</label>
          <input
            type="text"
            value={host}
            onChange={e => { setHost(e.target.value); setError(null); }}
            onKeyDown={e => e.key === "Enter" && handleScan()}
            placeholder="e.g. 192.168.1.1 or scanme.nmap.org"
            className="w-full px-3 py-2 bg-white border-2 border-slate-200 rounded-lg text-slate-800 text-xs placeholder-slate-400 focus:outline-none focus:border-violet-500 focus:bg-white transition-all"
          />
        </div>

        {/* Mode */}
        <div>
          <label className="block text-xs font-semibold text-slate-700 mb-1">Scan Mode</label>
          <div className="grid grid-cols-3 gap-2">
            {(["common","range","custom"] as ScanMode[]).map(m => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className={`py-1.5 rounded-lg text-xs font-semibold border-2 transition-all capitalize ${
                  mode === m
                    ? "bg-violet-600 border-violet-600 text-white shadow-md shadow-violet-600/20"
                    : "bg-white border-slate-200 text-slate-600 hover:border-violet-300"
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>

        {/* Range inputs */}
        {mode === "range" && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Start Port</label>
              <input type="number" min={1} max={65535} value={startPort}
                onChange={e => setStartPort(Number(e.target.value))}
                className="w-full px-3 py-2 bg-white border-2 border-slate-200 rounded-lg text-slate-800 text-xs focus:outline-none focus:border-violet-500 transition-all"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">End Port</label>
              <input type="number" min={1} max={65535} value={endPort}
                onChange={e => setEndPort(Number(e.target.value))}
                className="w-full px-3 py-2 bg-white border-2 border-slate-200 rounded-lg text-slate-800 text-xs focus:outline-none focus:border-violet-500 transition-all"
              />
            </div>
          </div>
        )}

        {/* Custom ports */}
        {mode === "custom" && (
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Port List <span className="text-slate-400 font-normal">(e.g. 80,443,8000-8080)</span>
            </label>
            <input type="text" value={customPorts}
              onChange={e => setCustomPorts(e.target.value)}
              placeholder="80,443,22,8000-8080"
              className="w-full px-3 py-2 bg-white border-2 border-slate-200 rounded-lg text-slate-800 text-xs focus:outline-none focus:border-violet-500 transition-all"
            />
          </div>
        )}

        {/* Timeout */}
        <div>
          <div className="flex justify-between mb-1">
            <label className="text-xs font-semibold text-slate-700">Timeout per port</label>
            <span className="text-xs font-bold text-violet-600">{timeout.toFixed(1)}s</span>
          </div>
          <input type="range" min={0.2} max={5} step={0.1} value={timeout}
            onChange={e => setTimeout_(Number(e.target.value))}
            className="w-full h-1.5 rounded-full appearance-none cursor-pointer accent-violet-600"
          />
          <div className="flex justify-between text-[10px] text-slate-400 mt-0.5">
            <span>0.2s (fast)</span><span>5.0s (thorough)</span>
          </div>
        </div>

        {/* Scan button */}
        <button
          onClick={handleScan}
          disabled={loading}
          className="w-full bg-violet-600 hover:bg-violet-700 disabled:bg-slate-300 disabled:cursor-not-allowed text-white font-semibold py-2.5 px-4 rounded-xl transition-all duration-200 shadow-lg shadow-violet-600/20 flex items-center justify-center gap-2 text-sm"
        >
          {loading
            ? <><span className="animate-spin inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full" /> Scanning...</>
            : <><Radar className="w-4 h-4" /> Start Scan</>
          }
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-2 bg-red-50 border-2 border-red-200 rounded-xl p-3 text-red-700 text-xs">
          <X className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-3">
          {/* Summary bar */}
          <div className="grid grid-cols-4 gap-2">
            {[
              { label: "Host",    value: result.host },
              { label: "Scanned", value: result.total_scanned },
              { label: "Open",    value: result.open_count },
              { label: "Time",    value: `${result.scan_time.toFixed(1)}s` },
            ].map(s => (
              <div key={s.label} className="bg-white border-2 border-slate-200 rounded-xl p-3 text-center">
                <p className="text-[10px] text-slate-400 font-mono uppercase tracking-wide">{s.label}</p>
                <p className="text-sm font-bold text-slate-800 mt-0.5 truncate">{s.value}</p>
              </div>
            ))}
          </div>

          {/* Risk filter */}
          <div className="flex gap-2 flex-wrap">
            {["all","high","medium","low","info"].map(r => (
              <button key={r} onClick={() => setFilterRisk(r)}
                className={`px-3 py-1 rounded-full text-[10px] font-bold border-2 capitalize transition-all ${
                  filterRisk === r
                    ? "bg-violet-600 border-violet-600 text-white"
                    : "bg-white border-slate-200 text-slate-500 hover:border-violet-300"
                }`}
              >
                {r === "all" ? `All (${result.ports.length})` : r}
              </button>
            ))}
          </div>

          {/* Port list */}
          {displayed.length === 0 ? (
            <div className="text-center py-8 text-slate-400 text-xs">
              No ports match this filter.
            </div>
          ) : (
            <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
              {displayed.map(p => {
                const meta = RISK_META[p.risk] ?? RISK_META.info;
                return (
                  <div key={p.port}
                    className={`flex items-center justify-between px-3 py-2 rounded-lg border-2 ${meta.bg}`}
                  >
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono text-xs font-bold text-slate-700 w-12">{p.port}</span>
                      <span className="text-xs text-slate-600">{p.service || "unknown"}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full ${meta.badge}`}>
                        {meta.icon}{p.risk}
                      </span>
                      <span className={`text-[10px] font-semibold capitalize ${
                        p.state === "open" ? "text-emerald-600" : "text-slate-400"
                      }`}>{p.state}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Idle state */}
      {!result && !loading && !error && (
        <div className="bg-gradient-to-br from-violet-50 to-indigo-50 rounded-xl p-4 border-2 border-violet-200 text-center">
          <Radar className="w-8 h-8 text-violet-400 mx-auto mb-2" />
          <p className="text-violet-800 font-semibold text-sm">Ready to scan</p>
          <p className="text-violet-500 text-xs mt-1">Enter a host and press Start Scan</p>
        </div>
      )}
    </div>
  );
}