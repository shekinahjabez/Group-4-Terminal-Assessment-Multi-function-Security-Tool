import { useState, useEffect, useRef, useCallback } from "react";
import { Activity, Play, Square, RefreshCw, Wifi } from "lucide-react";

const API = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

// ── Types ─────────────────────────────────────────────────────────────────────
interface Packet {
  id:        number;
  time:      string;
  src_ip:    string;
  dst_ip:    string;
  src_port:  number | null;
  dst_port:  number | null;
  protocol:  string;
  length:    number;
  flags?:    string;
  info?:     string;
}

interface TrafficStats {
  total:   number;
  tcp:     number;
  udp:     number;
  icmp:    number;
  other:   number;
}

const PROTO_STYLE: Record<string, string> = {
  TCP:  "bg-sky-100 text-sky-700 border-sky-200",
  UDP:  "bg-emerald-100 text-emerald-700 border-emerald-200",
  ICMP: "bg-violet-100 text-violet-700 border-violet-200",
  HTTP: "bg-orange-100 text-orange-700 border-orange-200",
  DNS:  "bg-amber-100 text-amber-700 border-amber-200",
};
const protoStyle = (p: string) =>
  PROTO_STYLE[p.toUpperCase()] ?? "bg-slate-100 text-slate-600 border-slate-200";

// ── Component ─────────────────────────────────────────────────────────────────
export function TrafficAnalyzer() {
  const [packets,  setPackets]  = useState<Packet[]>([]);
  const [stats,    setStats]    = useState<TrafficStats>({ total:0,tcp:0,udp:0,icmp:0,other:0 });
  const [running,  setRunning]  = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [duration, setDuration] = useState(15);

  // Filters
  const [filterProto, setFilterProto] = useState("");
  const [filterIP,    setFilterIP]    = useState("");
  const [filterSrc,   setFilterSrc]   = useState("");
  const [filterDst,   setFilterDst]   = useState("");

  const esRef      = useRef<EventSource | null>(null);
  const packetId   = useRef(0);
  const tbodyRef   = useRef<HTMLTableSectionElement>(null);

  const addPacket = useCallback((pkt: Omit<Packet,"id">) => {
    const withId: Packet = { ...pkt, id: ++packetId.current };
    setPackets(prev => [withId, ...prev].slice(0, 200));
    setStats(prev => {
      const proto = (pkt.protocol || "").toUpperCase();
      return {
        total: prev.total + 1,
        tcp:   prev.tcp   + (proto === "TCP"  ? 1 : 0),
        udp:   prev.udp   + (proto === "UDP"  ? 1 : 0),
        icmp:  prev.icmp  + (proto === "ICMP" ? 1 : 0),
        other: prev.other + (!["TCP","UDP","ICMP"].includes(proto) ? 1 : 0),
      };
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
    setRunning(true);

    const params = new URLSearchParams({
      duration: String(duration),
      ...(filterProto && { protocol: filterProto }),
      ...(filterIP    && { ip:       filterIP    }),
      ...(filterSrc   && { src_ip:   filterSrc   }),
      ...(filterDst   && { dst_ip:   filterDst   }),
    });

    const url = `${API}/api/traffic/stream?${params}`;
    const es  = new EventSource(url);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.done) { stopStream(); return; }
        if (data.error) { setError(String(data.error)); stopStream(); return; }
        addPacket(data as Omit<Packet,"id">);
      } catch { /* skip malformed */ }
    };

    es.onerror = () => {
      setError("Stream connection lost. The backend may have ended the capture.");
      stopStream();
    };
  }, [API, duration, filterProto, filterIP, filterSrc, filterDst, addPacket, stopStream]);

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
      const list: Omit<Packet,"id">[] = Array.isArray(data) ? data : (data.packets ?? []);
      list.forEach(addPacket);
    } catch (err: any) {
      setError(err?.message ?? "Snapshot failed.");
    }
  };

  const clearAll = () => {
    stopStream();
    setPackets([]);
    setStats({ total:0, tcp:0, udp:0, icmp:0, other:0 });
    packetId.current = 0;
    setError(null);
  };

  // Auto-scroll to top (newest packets are prepended)
  useEffect(() => {
    tbodyRef.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [packets.length]);

  // Cleanup on unmount
  useEffect(() => () => { esRef.current?.close(); }, []);

  return (
    <div className="space-y-4 h-full overflow-y-auto pr-1">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-800 mb-0.5">Traffic Analyzer</h2>
        <p className="text-slate-600 text-xs">Live packet capture via SSE stream (Python backend)</p>
      </div>

      {/* Controls */}
      <div className="bg-slate-50 border-2 border-slate-200 rounded-xl p-4 space-y-3">

        {/* Filters row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <div>
            <label className="block text-[10px] font-semibold text-slate-600 mb-1">Protocol</label>
            <select value={filterProto} onChange={e => setFilterProto(e.target.value)}
              className="w-full px-2 py-1.5 bg-white border-2 border-slate-200 rounded-lg text-slate-700 text-xs focus:outline-none focus:border-rose-400 transition-all"
            >
              <option value="">All</option>
              {["tcp","udp","icmp"].map(p => (
                <option key={p} value={p}>{p.toUpperCase()}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[10px] font-semibold text-slate-600 mb-1">IP (src or dst)</label>
            <input type="text" value={filterIP} onChange={e => setFilterIP(e.target.value)}
              placeholder="192.168.1.x"
              className="w-full px-2 py-1.5 bg-white border-2 border-slate-200 rounded-lg text-slate-700 text-xs focus:outline-none focus:border-rose-400 transition-all placeholder-slate-300"
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold text-slate-600 mb-1">Source IP</label>
            <input type="text" value={filterSrc} onChange={e => setFilterSrc(e.target.value)}
              placeholder="src only"
              className="w-full px-2 py-1.5 bg-white border-2 border-slate-200 rounded-lg text-slate-700 text-xs focus:outline-none focus:border-rose-400 transition-all placeholder-slate-300"
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold text-slate-600 mb-1">Dest IP</label>
            <input type="text" value={filterDst} onChange={e => setFilterDst(e.target.value)}
              placeholder="dst only"
              className="w-full px-2 py-1.5 bg-white border-2 border-slate-200 rounded-lg text-slate-700 text-xs focus:outline-none focus:border-rose-400 transition-all placeholder-slate-300"
            />
          </div>
        </div>

        {/* Duration slider */}
        <div>
          <div className="flex justify-between mb-1">
            <label className="text-[10px] font-semibold text-slate-600">Capture duration</label>
            <span className="text-[10px] font-bold text-rose-600">{duration}s</span>
          </div>
          <input type="range" min={5} max={60} step={5} value={duration}
            onChange={e => setDuration(Number(e.target.value))}
            disabled={running}
            className="w-full h-1.5 rounded-full appearance-none cursor-pointer accent-rose-500 disabled:opacity-50"
          />
          <div className="flex justify-between text-[10px] text-slate-400 mt-0.5">
            <span>5s</span><span>60s</span>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex gap-2 flex-wrap">
          {!running ? (
            <button onClick={startStream}
              className="flex-1 bg-rose-600 hover:bg-rose-700 text-white font-semibold py-2 px-4 rounded-lg transition-all text-xs flex items-center justify-center gap-1.5 shadow-lg shadow-rose-600/20"
            >
              <Play className="w-3.5 h-3.5" /> Start Live Stream
            </button>
          ) : (
            <button onClick={stopStream}
              className="flex-1 bg-slate-700 hover:bg-slate-800 text-white font-semibold py-2 px-4 rounded-lg transition-all text-xs flex items-center justify-center gap-1.5"
            >
              <Square className="w-3.5 h-3.5" /> Stop
            </button>
          )}
          <button onClick={takeSnapshot} disabled={running}
            className="bg-white border-2 border-rose-300 hover:bg-rose-50 disabled:opacity-40 disabled:cursor-not-allowed text-rose-700 font-semibold py-2 px-4 rounded-lg transition-all text-xs flex items-center justify-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Snapshot
          </button>
          <button onClick={clearAll}
            className="bg-white border-2 border-slate-200 hover:bg-slate-50 text-slate-600 font-semibold py-2 px-4 rounded-lg transition-all text-xs flex items-center justify-center gap-1.5"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-50 border-2 border-red-200 rounded-xl p-3 text-red-700 text-xs flex items-start gap-2">
          <span className="font-bold flex-shrink-0">Error:</span>
          <span>{error}</span>
        </div>
      )}

      {/* Stats pills */}
      {stats.total > 0 && (
        <div className="flex gap-2 flex-wrap">
          {[
            { label: "Total",  val: stats.total, style: "bg-slate-100 text-slate-700 border-slate-200" },
            { label: "TCP",    val: stats.tcp,   style: "bg-sky-100 text-sky-700 border-sky-200" },
            { label: "UDP",    val: stats.udp,   style: "bg-emerald-100 text-emerald-700 border-emerald-200" },
            { label: "ICMP",   val: stats.icmp,  style: "bg-violet-100 text-violet-700 border-violet-200" },
            { label: "Other",  val: stats.other, style: "bg-amber-100 text-amber-700 border-amber-200" },
          ].map(s => (
            <div key={s.label} className={`px-3 py-1 rounded-full border text-[10px] font-bold ${s.style}`}>
              {s.label}: {s.val}
              {stats.total > 0 && s.label !== "Total" && (
                <span className="ml-1 opacity-60">({Math.round(s.val / stats.total * 100)}%)</span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Live indicator */}
      {running && (
        <div className="flex items-center gap-2 text-xs text-rose-600 font-semibold">
          <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse inline-block" />
          Live capture running — {packets.length} packets captured
        </div>
      )}

      {/* Packet table */}
      {packets.length > 0 ? (
        <div className="overflow-x-auto rounded-xl border-2 border-slate-200">
          <table className="w-full text-[10px] font-mono border-collapse">
            <thead>
              <tr className="bg-slate-100 text-slate-500 uppercase tracking-wide">
                {["#","Time","Src IP","Dst IP","Proto","Src Port","Dst Port","Size","Flags/Info"].map(h => (
                  <th key={h} className="px-2 py-2 text-left font-semibold border-b-2 border-slate-200 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody ref={tbodyRef}>
              {packets.map((p, idx) => (
                <tr key={p.id}
                  className={`border-b border-slate-100 transition-colors hover:bg-slate-50 ${idx === 0 && running ? "bg-rose-50" : ""}`}
                >
                  <td className="px-2 py-1.5 text-slate-400">{p.id}</td>
                  <td className="px-2 py-1.5 text-slate-500 whitespace-nowrap">{p.time}</td>
                  <td className="px-2 py-1.5 text-slate-700 whitespace-nowrap">{p.src_ip || "—"}</td>
                  <td className="px-2 py-1.5 text-slate-700 whitespace-nowrap">{p.dst_ip || "—"}</td>
                  <td className="px-2 py-1.5">
                    <span className={`inline-block px-1.5 py-0.5 rounded border text-[9px] font-bold ${protoStyle(p.protocol)}`}>
                      {p.protocol}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 text-slate-500">{p.src_port ?? "—"}</td>
                  <td className="px-2 py-1.5 text-slate-500">{p.dst_port ?? "—"}</td>
                  <td className="px-2 py-1.5 text-slate-500">{p.length}B</td>
                  <td className="px-2 py-1.5 text-slate-400 max-w-[140px] truncate">{p.flags || p.info || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        !running && !error && (
          <div className="bg-gradient-to-br from-rose-50 to-pink-50 rounded-xl p-6 border-2 border-rose-200 text-center">
            <Activity className="w-8 h-8 text-rose-400 mx-auto mb-2" />
            <p className="text-rose-800 font-semibold text-sm">No traffic captured yet</p>
            <p className="text-rose-500 text-xs mt-1">
              Press <strong>Start Live Stream</strong> to begin capture, or <strong>Snapshot</strong> for a quick 20-packet sample.
            </p>
          </div>
        )
      )}
    </div>
  );
}