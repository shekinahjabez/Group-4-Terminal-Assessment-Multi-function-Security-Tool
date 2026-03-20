import { useState, useEffect, useRef, useCallback } from "react";
import { Activity, Play, Square, RefreshCw } from "lucide-react";

const API = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

// ── Types ─────────────────────────────────────────────────────────────────────
interface Packet {
  id:       number;
  time:     string;
  src_ip:   string;
  dst_ip:   string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length:   number;
  flags:    string;
  suspicious: boolean;
}

interface TrafficStats {
  total: number;
  tcp:   number;
  udp:   number;
  icmp:  number;
  other: number;
}

const PROTO_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  TCP:  { bg: "#e0f2fe", text: "#0369a1", border: "#bae6fd" },
  UDP:  { bg: "#d1fae5", text: "#065f46", border: "#a7f3d0" },
  ICMP: { bg: "#ede9fe", text: "#5b21b6", border: "#ddd6fe" },
  HTTP: { bg: "#ffedd5", text: "#9a3412", border: "#fed7aa" },
  DNS:  { bg: "#fef9c3", text: "#713f12", border: "#fde68a" },
};
const protoColor = (p: string) =>
  PROTO_COLORS[(p || "").toUpperCase()] ?? { bg: "#f1f5f9", text: "#475569", border: "#cbd5e1" };

// ── Parse a raw backend packet into our Packet shape ─────────────────────────
// Backend shape: { src, dst, protocol, flag, bytes, suspicious, ts, summary }
// src/dst are "IP:PORT" strings
function parseRawPacket(raw: Record<string, unknown>, id: number): Packet {
  const splitAddr = (addr: string) => {
    if (!addr) return { ip: "—", port: null };
    const lastColon = addr.lastIndexOf(":");
    if (lastColon === -1) return { ip: addr, port: null };
    const ip   = addr.slice(0, lastColon);
    const port = parseInt(addr.slice(lastColon + 1), 10);
    return { ip, port: isNaN(port) ? null : port };
  };

  const src = splitAddr(String(raw.src || raw.src_ip || ""));
  const dst = splitAddr(String(raw.dst || raw.dst_ip || ""));

  return {
    id,
    time:       String(raw.ts || raw.time || raw.timestamp || ""),
    src_ip:     src.ip,
    dst_ip:     dst.ip,
    src_port:   src.port,
    dst_port:   dst.port,
    protocol:   String(raw.protocol || raw.proto || "UNKNOWN"),
    length:     Number(raw.bytes || raw.length || raw.size || 0),
    flags:      String(raw.flag || raw.flags || raw.summary || "—"),
    suspicious: Boolean(raw.suspicious),
  };
}

// ── Component ─────────────────────────────────────────────────────────────────
export function TrafficAnalyzer() {
  const [packets,  setPackets]  = useState<Packet[]>([]);
  const [stats,    setStats]    = useState<TrafficStats>({ total:0, tcp:0, udp:0, icmp:0, other:0 });
  const [running,  setRunning]  = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [duration, setDuration] = useState(15);

  const [filterProto, setFilterProto] = useState("");
  const [filterIP,    setFilterIP]    = useState("");
  const [filterSrc,   setFilterSrc]   = useState("");
  const [filterDst,   setFilterDst]   = useState("");

  const esRef    = useRef<EventSource | null>(null);
  const packetId = useRef(0);
  const gotAny   = useRef(false);

  const addPackets = useCallback((raws: Record<string, unknown>[]) => {
    if (!raws.length) return;
    gotAny.current = true;
    const newPkts = raws.map(r => parseRawPacket(r, ++packetId.current));
    setPackets(prev => [...newPkts, ...prev].slice(0, 300));
    setStats(prev => {
      let { total, tcp, udp, icmp, other } = prev;
      for (const p of newPkts) {
        total++;
        const proto = p.protocol.toUpperCase();
        if      (proto === "TCP")  tcp++;
        else if (proto === "UDP")  udp++;
        else if (proto === "ICMP") icmp++;
        else                       other++;
      }
      return { total, tcp, udp, icmp, other };
    });
  }, []);

  const stopStream = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
    setRunning(false);
  }, []);

  const startStream = useCallback(() => {
    if (!API) { setError("VITE_API_BASE_URL is not set."); return; }
    stopStream();
    setError(null);
    gotAny.current = false;
    setRunning(true);

    const params = new URLSearchParams({ duration: String(duration) });
    if (filterProto) params.set("protocol", filterProto);
    if (filterIP)    params.set("ip",       filterIP);
    if (filterSrc)   params.set("src_ip",   filterSrc);
    if (filterDst)   params.set("dst_ip",   filterDst);

    const es = new EventSource(`${API}/api/traffic/stream?${params}`);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);

        if (data.done)  { stopStream(); return; }
        if (data.error) { setError(String(data.error)); stopStream(); return; }

        // Backend sends batches: { packets: [...], stats: {...} }
        if (Array.isArray(data.packets)) {
          addPackets(data.packets);
        } else if (data.src || data.src_ip) {
          // Single-packet format fallback
          addPackets([data]);
        }
      } catch (err) {
        console.error("Malformed SSE packet:", err, e.data);
      }
    };

    es.onerror = () => {
      stopStream();
      if (!gotAny.current) {
        setError("Stream ended with no packets. Check that the backend is running and has network access.");
      }
    };
  }, [API, duration, filterProto, filterIP, filterSrc, filterDst, addPackets, stopStream]);

  const takeSnapshot = async () => {
    if (!API) { setError("VITE_API_BASE_URL is not set."); return; }
    setError(null);
    try {
      const r = await fetch(`${API}/api/traffic/snapshot`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ count: 20 }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data?.detail ?? `Error ${r.status}`);
      const list: Record<string, unknown>[] = Array.isArray(data)
        ? data
        : Array.isArray(data.packets) ? data.packets : [];
      addPackets(list);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Snapshot failed.");
    }
  };

  const clearAll = () => {
    stopStream();
    setPackets([]);
    setStats({ total:0, tcp:0, udp:0, icmp:0, other:0 });
    packetId.current = 0;
    gotAny.current   = false;
    setError(null);
  };

  useEffect(() => () => { esRef.current?.close(); }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* Header */}
      <div>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "#1e293b", margin: 0 }}>Traffic Analyzer</h2>
        <p style={{ fontSize: 12, color: "#64748b", margin: "4px 0 0" }}>Live packet capture via SSE stream (Python backend)</p>
      </div>

      {/* Controls card */}
      <div style={{ backgroundColor: "#f8fafc", border: "2px solid #e2e8f0", borderRadius: 12, padding: 16, display: "flex", flexDirection: "column", gap: 12 }}>

        {/* Filter row */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>
          {[
            { label: "Protocol", el: (
              <select value={filterProto} onChange={e => setFilterProto(e.target.value)}
                style={{ width: "100%", padding: "6px 8px", border: "2px solid #e2e8f0", borderRadius: 8, fontSize: 12, color: "#334155", backgroundColor: "#fff", outline: "none" }}
              >
                <option value="">All</option>
                {["tcp","udp","icmp"].map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
              </select>
            )},
            { label: "IP (src or dst)", el: (
              <input type="text" value={filterIP} onChange={e => setFilterIP(e.target.value)}
                placeholder="192.168.1.x"
                style={{ width: "100%", padding: "6px 8px", border: "2px solid #e2e8f0", borderRadius: 8, fontSize: 12, color: "#334155", backgroundColor: "#fff", outline: "none", boxSizing: "border-box" }}
              />
            )},
            { label: "Source IP", el: (
              <input type="text" value={filterSrc} onChange={e => setFilterSrc(e.target.value)}
                placeholder="src only"
                style={{ width: "100%", padding: "6px 8px", border: "2px solid #e2e8f0", borderRadius: 8, fontSize: 12, color: "#334155", backgroundColor: "#fff", outline: "none", boxSizing: "border-box" }}
              />
            )},
            { label: "Dest IP", el: (
              <input type="text" value={filterDst} onChange={e => setFilterDst(e.target.value)}
                placeholder="dst only"
                style={{ width: "100%", padding: "6px 8px", border: "2px solid #e2e8f0", borderRadius: 8, fontSize: 12, color: "#334155", backgroundColor: "#fff", outline: "none", boxSizing: "border-box" }}
              />
            )},
          ].map(({ label, el }) => (
            <div key={label}>
              <label style={{ display: "block", fontSize: 10, fontWeight: 600, color: "#64748b", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</label>
              {el}
            </div>
          ))}
        </div>

        {/* Duration slider */}
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <label style={{ fontSize: 10, fontWeight: 600, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.05em" }}>Capture duration</label>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#e11d48" }}>{duration}s</span>
          </div>
          <input type="range" min={5} max={60} step={5} value={duration}
            onChange={e => setDuration(Number(e.target.value))}
            disabled={running}
            style={{ width: "100%", accentColor: "#e11d48", cursor: running ? "not-allowed" : "pointer" }}
          />
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ fontSize: 10, color: "#94a3b8" }}>5s</span>
            <span style={{ fontSize: 10, color: "#94a3b8" }}>60s</span>
          </div>
        </div>

        {/* Buttons */}
        <div style={{ display: "flex", gap: 8 }}>
          {!running ? (
            <button onClick={startStream}
              style={{ flex: 1, backgroundColor: "#e11d48", color: "#fff", border: "none", borderRadius: 8, padding: "10px 16px", fontWeight: 600, fontSize: 13, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}
              onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#be123c")}
              onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#e11d48")}
            >
              <Play style={{ width: 14, height: 14 }} />
              Start Live Stream
            </button>
          ) : (
            <button onClick={stopStream}
              style={{ flex: 1, backgroundColor: "#334155", color: "#fff", border: "none", borderRadius: 8, padding: "10px 16px", fontWeight: 600, fontSize: 13, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6 }}
            >
              <Square style={{ width: 14, height: 14 }} />
              Stop
            </button>
          )}
          <button onClick={takeSnapshot} disabled={running}
            style={{ backgroundColor: "#fff", color: "#e11d48", border: "2px solid #fecdd3", borderRadius: 8, padding: "10px 16px", fontWeight: 600, fontSize: 13, cursor: running ? "not-allowed" : "pointer", opacity: running ? 0.4 : 1, display: "flex", alignItems: "center", gap: 6 }}
          >
            <RefreshCw style={{ width: 13, height: 13 }} />
            Snapshot
          </button>
          <button onClick={clearAll}
            style={{ backgroundColor: "#fff", color: "#64748b", border: "2px solid #e2e8f0", borderRadius: 8, padding: "10px 16px", fontWeight: 600, fontSize: 13, cursor: "pointer" }}
          >
            Clear
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{ backgroundColor: "#fef2f2", border: "2px solid #fecaca", borderRadius: 10, padding: "10px 14px", color: "#dc2626", fontSize: 12, display: "flex", gap: 8 }}>
          <span style={{ fontWeight: 700 }}>Error:</span>
          <span>{error}</span>
        </div>
      )}

      {/* Stats */}
      {stats.total > 0 && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {[
            { label: "Total", val: stats.total,  bg: "#f1f5f9", text: "#334155", border: "#e2e8f0" },
            { label: "TCP",   val: stats.tcp,     bg: "#e0f2fe", text: "#0369a1", border: "#bae6fd" },
            { label: "UDP",   val: stats.udp,     bg: "#d1fae5", text: "#065f46", border: "#a7f3d0" },
            { label: "ICMP",  val: stats.icmp,    bg: "#ede9fe", text: "#5b21b6", border: "#ddd6fe" },
            { label: "Other", val: stats.other,   bg: "#fef9c3", text: "#713f12", border: "#fde68a" },
          ].map(s => (
            <div key={s.label} style={{ backgroundColor: s.bg, border: `1px solid ${s.border}`, borderRadius: 999, padding: "4px 12px", fontSize: 11, fontWeight: 700, color: s.text }}>
              {s.label}: {s.val}
              {stats.total > 0 && s.label !== "Total" && (
                <span style={{ opacity: 0.6, marginLeft: 4 }}>({Math.round(s.val / stats.total * 100)}%)</span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Live indicator */}
      {running && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "#e11d48", fontWeight: 600 }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", backgroundColor: "#e11d48", display: "inline-block", animation: "pulse 1s infinite" }} />
          Live capture running — {packets.length} packets captured
        </div>
      )}

      {/* Packet table */}
      {packets.length > 0 ? (
        <div style={{ overflowX: "auto", borderRadius: 10, border: "2px solid #e2e8f0" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "monospace" }}>
            <thead>
              <tr style={{ backgroundColor: "#f1f5f9" }}>
                {["#","Time","Src IP","Dst IP","Proto","Src Port","Dst Port","Size","Flags"].map(h => (
                  <th key={h} style={{ padding: "8px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.05em", borderBottom: "2px solid #e2e8f0", whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {packets.map((p, idx) => {
                const pc = protoColor(p.protocol);
                return (
                  <tr key={p.id} style={{ borderBottom: "1px solid #f1f5f9", backgroundColor: p.suspicious ? "#fff7ed" : idx === 0 && running ? "#fff1f2" : "#fff" }}>
                    <td style={{ padding: "7px 10px", color: "#94a3b8" }}>{p.id}</td>
                    <td style={{ padding: "7px 10px", color: "#64748b", whiteSpace: "nowrap" }}>{p.time ? p.time.slice(11, 23) : "—"}</td>
                    <td style={{ padding: "7px 10px", color: "#334155", whiteSpace: "nowrap" }}>{p.src_ip}</td>
                    <td style={{ padding: "7px 10px", color: "#334155", whiteSpace: "nowrap" }}>{p.dst_ip}</td>
                    <td style={{ padding: "7px 10px" }}>
                      <span style={{ backgroundColor: pc.bg, color: pc.text, border: `1px solid ${pc.border}`, borderRadius: 4, padding: "2px 6px", fontSize: 10, fontWeight: 700 }}>
                        {p.protocol}
                      </span>
                    </td>
                    <td style={{ padding: "7px 10px", color: "#64748b" }}>{p.src_port ?? "—"}</td>
                    <td style={{ padding: "7px 10px", color: "#64748b" }}>{p.dst_port ?? "—"}</td>
                    <td style={{ padding: "7px 10px", color: "#64748b" }}>{p.length}B</td>
                    <td style={{ padding: "7px 10px", color: p.suspicious ? "#ea580c" : "#94a3b8", maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {p.suspicious ? "⚠ " : ""}{p.flags}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        !running && !error && (
          <div style={{ backgroundColor: "#fff1f2", border: "2px solid #fecdd3", borderRadius: 12, padding: 24, textAlign: "center" }}>
            <Activity style={{ width: 32, height: 32, color: "#fb7185", margin: "0 auto 8px" }} />
            <p style={{ fontSize: 14, fontWeight: 600, color: "#9f1239", margin: "0 0 4px" }}>No traffic captured yet</p>
            <p style={{ fontSize: 12, color: "#fb7185", margin: 0 }}>
              Press <strong>Start Live Stream</strong> to begin, or <strong>Snapshot</strong> for a quick 20-packet sample.
            </p>
          </div>
        )
      )}
    </div>
  );
}