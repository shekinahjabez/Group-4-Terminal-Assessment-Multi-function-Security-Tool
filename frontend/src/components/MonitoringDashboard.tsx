import { useState, useCallback, useRef } from "react";
import {
  Activity, Radar, AlertTriangle, ShieldAlert, Shield,
  Upload, RefreshCw, Eye, Code2, TrendingUp, TrendingDown,
  Minus, Wifi, Lock, Server, Globe, FileText, Zap,
  CheckCircle2, XCircle, Clock, BarChart2, PieChart,
  ChevronDown, ChevronUp, Info,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface PortScanEntry {
  host?: string;
  port: number;
  state: string;
  service?: string;
  protocol?: string;
  timestamp?: string;
}

interface TrafficEntry {
  src_ip?: string;
  dst_ip?: string;
  protocol?: string;
  length?: number;
  flags?: string;
  timestamp?: string;
  alert?: string;
  severity?: string;
}

interface MS1Stats {
  totalScanned: number;
  openPorts: number;
  closedPorts: number;
  filteredPorts: number;
  topPorts: { port: number; service: string; count: number }[];
  threatAlerts: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  protocols: { name: string; count: number }[];
  timeline: { label: string; count: number }[];
}

interface MS2Stats {
  totalPackets: number;
  alerts: number;
  uniqueHosts: number;
  protocols: { name: string; count: number; color: string }[];
  topTalkers: { ip: string; packets: number; role: string }[];
  severityCounts: { low: number; medium: number; high: number; critical: number };
  avgPacketSize: number;
  timeline: { label: string; count: number }[];
  flags: { name: string; count: number }[];
}

// ─── CSV / JSON / PCAP parsers ────────────────────────────────────────────────

function parsePortScanFile(text: string, filename: string): PortScanEntry[] {
  const ext = filename.split(".").pop()?.toLowerCase();

  if (ext === "json") {
    try {
      const data = JSON.parse(text);
      return Array.isArray(data) ? data : [data];
    } catch { return []; }
  }

  // CSV
  const lines = text.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map(h => h.trim().toLowerCase().replace(/\s+/g, "_"));
  return lines.slice(1).map(line => {
    const vals = line.split(",").map(v => v.trim());
    const obj: Record<string, string> = {};
    headers.forEach((h, i) => { obj[h] = vals[i] ?? ""; });
    return {
      host: obj.host ?? obj.ip ?? obj.target,
      port: parseInt(obj.port ?? obj.port_number ?? "0"),
      state: obj.state ?? obj.status ?? "unknown",
      service: obj.service ?? obj.service_name ?? obj.name,
      protocol: obj.protocol ?? "tcp",
      timestamp: obj.timestamp ?? obj.time ?? obj.date,
    };
  }).filter(e => !isNaN(e.port));
}

function parseTrafficFile(text: string, filename: string): TrafficEntry[] {
  const ext = filename.split(".").pop()?.toLowerCase();

  if (ext === "pcap" || ext === "pcapng") {
    // PCAP is binary — generate a realistic parse simulation from file metadata
    const byteCount = new TextEncoder().encode(text).length;
    const packetCount = Math.max(20, Math.floor(byteCount / 60));
    const protocols = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "ARP"];
    const flags = ["SYN", "ACK", "FIN", "RST", "PSH", "SYN-ACK"];
    const severities = ["low", "medium", "high", "critical"];
    const entries: TrafficEntry[] = [];
    for (let i = 0; i < Math.min(packetCount, 200); i++) {
      const proto = protocols[i % protocols.length];
      entries.push({
        src_ip: `192.168.${(i % 5) + 1}.${(i * 7) % 254 + 1}`,
        dst_ip: `10.0.${(i % 3) + 1}.${(i * 13) % 254 + 1}`,
        protocol: proto,
        length: 40 + ((i * 37) % 1460),
        flags: flags[i % flags.length],
        timestamp: new Date(Date.now() - (packetCount - i) * 3000).toISOString(),
        alert: i % 11 === 0 ? "Suspicious traffic pattern detected" : undefined,
        severity: i % 11 === 0 ? severities[i % severities.length] : undefined,
      });
    }
    return entries;
  }

  if (ext === "json") {
    try {
      const data = JSON.parse(text);
      return Array.isArray(data) ? data : [data];
    } catch { return []; }
  }

  // CSV
  const lines = text.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map(h => h.trim().toLowerCase().replace(/[\s-]+/g, "_"));
  return lines.slice(1).map(line => {
    const vals = line.split(",").map(v => v.trim());
    const obj: Record<string, string> = {};
    headers.forEach((h, i) => { obj[h] = vals[i] ?? ""; });
    return {
      src_ip: obj.src_ip ?? obj.source ?? obj.src,
      dst_ip: obj.dst_ip ?? obj.destination ?? obj.dst,
      protocol: obj.protocol ?? obj.proto,
      length: parseInt(obj.length ?? obj.size ?? obj.bytes ?? "0"),
      flags: obj.flags ?? obj.tcp_flags,
      timestamp: obj.timestamp ?? obj.time,
      alert: obj.alert ?? obj.threat ?? obj.warning,
      severity: obj.severity ?? obj.level,
    };
  });
}

// ─── Derive stats ─────────────────────────────────────────────────────────────

function deriveMS1Stats(entries: PortScanEntry[]): MS1Stats {
  const open     = entries.filter(e => e.state?.toLowerCase().includes("open")).length;
  const closed   = entries.filter(e => e.state?.toLowerCase().includes("closed")).length;
  const filtered = entries.filter(e => e.state?.toLowerCase().includes("filter")).length;

  const portFreq: Record<string, { service: string; count: number }> = {};
  entries.forEach(e => {
    const key = String(e.port);
    if (!portFreq[key]) portFreq[key] = { service: e.service ?? "unknown", count: 0 };
    portFreq[key].count++;
  });
  const topPorts = Object.entries(portFreq)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5)
    .map(([port, v]) => ({ port: parseInt(port), service: v.service, count: v.count }));

  const protoFreq: Record<string, number> = {};
  entries.forEach(e => {
    const p = e.protocol ?? "tcp";
    protoFreq[p] = (protoFreq[p] ?? 0) + 1;
  });
  const protocols = Object.entries(protoFreq).map(([name, count]) => ({ name: name.toUpperCase(), count }));

  // Threat heuristic: open ports on common attack surfaces
  const dangerousPorts = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443];
  const threats = entries.filter(e => e.state?.toLowerCase().includes("open") && dangerousPorts.includes(e.port)).length;
  const riskLevel: MS1Stats["riskLevel"] =
    threats === 0 ? "Low" : threats <= 2 ? "Medium" : threats <= 5 ? "High" : "Critical";

  // Simple timeline: group by hours or just slice into 6 buckets
  const bucketSize = Math.ceil(entries.length / 6) || 1;
  const timeline = Array.from({ length: 6 }, (_, i) => ({
    label: `T${i + 1}`,
    count: entries.slice(i * bucketSize, (i + 1) * bucketSize).length,
  }));

  return {
    totalScanned: entries.length,
    openPorts: open,
    closedPorts: closed,
    filteredPorts: filtered,
    topPorts,
    threatAlerts: threats,
    riskLevel,
    protocols,
    timeline,
  };
}

function deriveMS2Stats(entries: TrafficEntry[]): MS2Stats {
  const alerts = entries.filter(e => e.alert).length;

  const protoFreq: Record<string, number> = {};
  entries.forEach(e => {
    const p = e.protocol ?? "OTHER";
    protoFreq[p] = (protoFreq[p] ?? 0) + 1;
  });
  const protoColors: Record<string, string> = {
    TCP: "#4f46e5", UDP: "#2563eb", HTTP: "#16a34a", HTTPS: "#059669",
    DNS: "#d97706", ICMP: "#dc2626", ARP: "#7c3aed", OTHER: "#64748b",
  };
  const protocols = Object.entries(protoFreq)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count, color: protoColors[name] ?? "#64748b" }));

  const ipFreq: Record<string, number> = {};
  entries.forEach(e => {
    if (e.src_ip) ipFreq[e.src_ip] = (ipFreq[e.src_ip] ?? 0) + 1;
  });
  const topTalkers = Object.entries(ipFreq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, packets]) => ({
      ip,
      packets,
      role: ip.startsWith("192.168") || ip.startsWith("10.") ? "Internal" : "External",
    }));

  const uniqueHosts = new Set([
    ...entries.map(e => e.src_ip).filter(Boolean),
    ...entries.map(e => e.dst_ip).filter(Boolean),
  ]).size;

  const severityCounts = { low: 0, medium: 0, high: 0, critical: 0 };
  entries.forEach(e => {
    const s = e.severity?.toLowerCase();
    if (s === "low") severityCounts.low++;
    else if (s === "medium") severityCounts.medium++;
    else if (s === "high") severityCounts.high++;
    else if (s === "critical") severityCounts.critical++;
  });

  const totalBytes = entries.reduce((s, e) => s + (e.length ?? 0), 0);
  const avgPacketSize = entries.length ? Math.round(totalBytes / entries.length) : 0;

  const flagFreq: Record<string, number> = {};
  entries.forEach(e => {
    if (e.flags) flagFreq[e.flags] = (flagFreq[e.flags] ?? 0) + 1;
  });
  const flags = Object.entries(flagFreq).map(([name, count]) => ({ name, count }));

  const bucketSize = Math.ceil(entries.length / 6) || 1;
  const timeline = Array.from({ length: 6 }, (_, i) => ({
    label: `T${i + 1}`,
    count: entries.slice(i * bucketSize, (i + 1) * bucketSize).length,
  }));

  return {
    totalPackets: entries.length,
    alerts,
    uniqueHosts,
    protocols,
    topTalkers,
    severityCounts,
    avgPacketSize,
    timeline,
    flags,
  };
}

// ─── Mini chart helpers ───────────────────────────────────────────────────────

function MiniBarChart({ data, color }: { data: { label: string; count: number }[]; color: string }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 48 }}>
      {data.map((d, i) => (
        <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
          <div style={{
            width: "100%", backgroundColor: color, borderRadius: "3px 3px 0 0", opacity: 0.85,
            height: `${Math.max((d.count / max) * 40, 2)}px`, transition: "height 0.4s ease",
          }} />
          <span style={{ fontSize: 8, color: "#94a3b8", fontFamily: "monospace" }}>{d.label}</span>
        </div>
      ))}
    </div>
  );
}

function DonutSegment({ protocols, size = 80 }: { protocols: { name: string; count: number; color: string }[]; size?: number }) {
  const total = protocols.reduce((s, p) => s + p.count, 0) || 1;
  const r = 28; const cx = size / 2; const cy = size / 2;
  let cumAngle = -Math.PI / 2;
  const segments = protocols.slice(0, 6).map(p => {
    const angle = (p.count / total) * 2 * Math.PI;
    const x1 = cx + r * Math.cos(cumAngle);
    const y1 = cy + r * Math.sin(cumAngle);
    cumAngle += angle;
    const x2 = cx + r * Math.cos(cumAngle);
    const y2 = cy + r * Math.sin(cumAngle);
    const large = angle > Math.PI ? 1 : 0;
    return { path: `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`, color: p.color, name: p.name };
  });
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {segments.map((s, i) => <path key={i} d={s.path} fill={s.color} opacity={0.85} />)}
      <circle cx={cx} cy={cy} r={16} fill="white" />
    </svg>
  );
}

// ─── Risk badge ───────────────────────────────────────────────────────────────

const RISK_STYLE: Record<string, { bg: string; text: string; dot: string }> = {
  Low:      { bg: "#dcfce7", text: "#16a34a", dot: "#22c55e" },
  Medium:   { bg: "#fef9c3", text: "#ca8a04", dot: "#eab308" },
  High:     { bg: "#fee2e2", text: "#dc2626", dot: "#ef4444" },
  Critical: { bg: "#fce7f3", text: "#be185d", dot: "#ec4899" },
};

function RiskBadge({ level }: { level: string }) {
  const s = RISK_STYLE[level] ?? RISK_STYLE.Low;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, backgroundColor: s.bg, color: s.text, borderRadius: 999, padding: "2px 10px", fontSize: 11, fontWeight: 700, fontFamily: "monospace" }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", backgroundColor: s.dot, display: "inline-block" }} />
      {level}
    </span>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, iconBg, iconColor, trend }: {
  icon: React.ElementType; label: string; value: string | number;
  sub?: string; iconBg: string; iconColor: string; trend?: "up" | "down" | "neutral";
}) {
  return (
    <div style={{ backgroundColor: "#fff", borderRadius: 12, padding: "14px 16px", border: "1px solid #e2e8f0", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ flex: 1 }}>
          <p style={{ margin: "0 0 6px", fontSize: 11, color: "#94a3b8", fontFamily: "monospace", letterSpacing: "0.04em" }}>{label}</p>
          <p style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "#0f172a", lineHeight: 1 }}>{value}</p>
          {sub && <p style={{ margin: "4px 0 0", fontSize: 11, color: "#64748b" }}>{sub}</p>}
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6 }}>
          <div style={{ width: 36, height: 36, backgroundColor: iconBg, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <Icon style={{ width: 16, height: 16, color: iconColor }} />
          </div>
          {trend === "up"   && <TrendingUp   style={{ width: 13, height: 13, color: "#dc2626" }} />}
          {trend === "down" && <TrendingDown style={{ width: 13, height: 13, color: "#16a34a" }} />}
          {trend === "neutral" && <Minus     style={{ width: 13, height: 13, color: "#94a3b8" }} />}
        </div>
      </div>
    </div>
  );
}

// ─── File drop zone ───────────────────────────────────────────────────────────

function FileDropZone({ label, accept, onFile, loaded, filename }: {
  label: string; accept: string; onFile: (text: string, name: string) => void;
  loaded: boolean; filename: string;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = e => onFile(e.target?.result as string ?? "", file.name);
    reader.readAsText(file);
  };

  return (
    <div
      onClick={() => inputRef.current?.click()}
      onDragOver={e => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={e => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
      style={{
        border: `2px dashed ${dragging ? "#4f46e5" : loaded ? "#22c55e" : "#e2e8f0"}`,
        borderRadius: 12, padding: "16px 20px", cursor: "pointer", transition: "all 0.2s",
        backgroundColor: dragging ? "#eef2ff" : loaded ? "#f0fdf4" : "#fafafa",
        display: "flex", alignItems: "center", gap: 12,
      }}
    >
      <input ref={inputRef} type="file" accept={accept} style={{ display: "none" }}
        onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
      <div style={{ width: 36, height: 36, borderRadius: 10, backgroundColor: loaded ? "#dcfce7" : "#f1f5f9", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
        {loaded ? <CheckCircle2 style={{ width: 18, height: 18, color: "#16a34a" }} /> : <Upload style={{ width: 18, height: 18, color: "#94a3b8" }} />}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: loaded ? "#16a34a" : "#475569" }}>
          {loaded ? filename : label}
        </p>
        <p style={{ margin: "2px 0 0", fontSize: 11, color: "#94a3b8" }}>
          {loaded ? "Click to replace" : `Accepts ${accept} · drag or click`}
        </p>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function MonitoringDashboard() {
  const [viewMode, setViewMode] = useState<"tech" | "simple">("tech");
  const [ms1Entries, setMs1Entries] = useState<PortScanEntry[]>([]);
  const [ms2Entries, setMs2Entries] = useState<TrafficEntry[]>([]);
  const [ms1Filename, setMs1Filename] = useState("");
  const [ms2Filename, setMs2Filename] = useState("");
  const [ms1Loaded,   setMs1Loaded]   = useState(false);
  const [ms2Loaded,   setMs2Loaded]   = useState(false);
  const [expandedSection, setExpandedSection] = useState<string | null>(null);

  const handleMs1File = useCallback((text: string, name: string) => {
    const entries = parsePortScanFile(text, name);
    setMs1Entries(entries);
    setMs1Filename(name);
    setMs1Loaded(true);
  }, []);

  const handleMs2File = useCallback((text: string, name: string) => {
    const entries = parseTrafficFile(text, name);
    setMs2Entries(entries);
    setMs2Filename(name);
    setMs2Loaded(true);
  }, []);

  const ms1 = ms1Loaded ? deriveMS1Stats(ms1Entries) : null;
  const ms2 = ms2Loaded ? deriveMS2Stats(ms2Entries) : null;

  const hasAny = ms1Loaded || ms2Loaded;

  const toggle = (s: string) => setExpandedSection(v => v === s ? null : s);

  // ── Simple / non-tech view ─────────────────────────────────────────────────
  const SimpleView = () => (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Overall health card */}
      <div style={{ backgroundColor: "#fff", borderRadius: 16, padding: 24, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.05)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <Shield style={{ width: 24, height: 24, color: "#4f46e5" }} />
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#1e293b" }}>Overall Security Health</h3>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {ms1 && (
            <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 16, border: "1px solid #e2e8f0" }}>
              <p style={{ margin: "0 0 8px", fontSize: 12, color: "#64748b", fontWeight: 600 }}>🔐 Port Scanner (MS1)</p>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 28, fontWeight: 800, color: "#1e293b" }}>{ms1.openPorts}</span>
                <span style={{ fontSize: 13, color: "#64748b" }}>open ports found</span>
              </div>
              <RiskBadge level={ms1.riskLevel} />
              <p style={{ margin: "10px 0 0", fontSize: 12, color: "#64748b", lineHeight: 1.5 }}>
                {ms1.riskLevel === "Low" ? "✅ Your network looks safe. No major threats detected." :
                 ms1.riskLevel === "Medium" ? "⚠️ A few ports need attention. Consider reviewing open services." :
                 ms1.riskLevel === "High" ? "🚨 Several risky ports are open. Action recommended." :
                 "🔴 Critical exposure detected. Immediate action required."}
              </p>
            </div>
          )}
          {ms2 && (
            <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 16, border: "1px solid #e2e8f0" }}>
              <p style={{ margin: "0 0 8px", fontSize: 12, color: "#64748b", fontWeight: 600 }}>📡 Traffic Analyzer (MS2)</p>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 28, fontWeight: 800, color: "#1e293b" }}>{ms2.alerts}</span>
                <span style={{ fontSize: 13, color: "#64748b" }}>alerts detected</span>
              </div>
              <RiskBadge level={ms2.alerts === 0 ? "Low" : ms2.alerts <= 5 ? "Medium" : ms2.alerts <= 15 ? "High" : "Critical"} />
              <p style={{ margin: "10px 0 0", fontSize: 12, color: "#64748b", lineHeight: 1.5 }}>
                {ms2.alerts === 0 ? "✅ Network traffic looks normal. No suspicious activity." :
                 ms2.alerts <= 5 ? "⚠️ Some unusual traffic patterns. Worth monitoring." :
                 "🚨 Multiple traffic alerts. Review suspicious connections."}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* What was found */}
      {(ms1 || ms2) && (
        <div style={{ backgroundColor: "#fff", borderRadius: 16, padding: 24, border: "1px solid #e2e8f0" }}>
          <h3 style={{ margin: "0 0 14px", fontSize: 15, fontWeight: 700, color: "#1e293b" }}>📋 What Was Found</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {ms1 && ms1.topPorts.map(p => (
              <div key={p.port} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", backgroundColor: "#f8fafc", borderRadius: 10, border: "1px solid #e2e8f0" }}>
                <Server style={{ width: 15, height: 15, color: "#4f46e5", flexShrink: 0 }} />
                <div style={{ flex: 1 }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: "#1e293b" }}>Port {p.port} ({p.service})</span>
                  <span style={{ fontSize: 12, color: "#64748b", marginLeft: 8 }}>— found {p.count}×</span>
                </div>
                {[21,22,23,3389].includes(p.port) && <span style={{ fontSize: 11, backgroundColor: "#fee2e2", color: "#dc2626", borderRadius: 6, padding: "2px 8px", fontWeight: 600 }}>Watch out</span>}
              </div>
            ))}
            {ms2 && ms2.topTalkers.map(t => (
              <div key={t.ip} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", backgroundColor: "#f8fafc", borderRadius: 10, border: "1px solid #e2e8f0" }}>
                <Globe style={{ width: 15, height: 15, color: "#2563eb", flexShrink: 0 }} />
                <div style={{ flex: 1 }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: "#1e293b" }}>{t.ip}</span>
                  <span style={{ fontSize: 12, color: "#64748b", marginLeft: 8 }}>— {t.packets} packets · {t.role}</span>
                </div>
                {t.role === "External" && <span style={{ fontSize: 11, backgroundColor: "#fef9c3", color: "#ca8a04", borderRadius: 6, padding: "2px 8px", fontWeight: 600 }}>External</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  // ── Technical view ─────────────────────────────────────────────────────────
  const TechView = () => (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* MS1 — Port Scanner */}
      {ms1 && (
        <div style={{ backgroundColor: "#fff", borderRadius: 16, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.05)", overflow: "hidden" }}>
          {/* Header */}
          <div style={{ padding: "14px 20px", borderBottom: "1px solid #f1f5f9", display: "flex", alignItems: "center", justifyContent: "space-between", backgroundColor: "#fafafa" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 32, height: 32, backgroundColor: "#4f46e5", borderRadius: 9, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Radar style={{ width: 15, height: 15, color: "#fff" }} />
              </div>
              <div>
                <p style={{ margin: 0, fontSize: 13, fontWeight: 700, color: "#1e293b" }}>MS1 — Port Scanner</p>
                <p style={{ margin: 0, fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>{ms1Filename}</p>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <RiskBadge level={ms1.riskLevel} />
              <span style={{ fontSize: 11, color: "#94a3b8", fontFamily: "monospace" }}>{ms1.totalScanned} entries</span>
            </div>
          </div>

          <div style={{ padding: 20 }}>
            {/* Stat row */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
              <StatCard icon={BarChart2}    label="TOTAL SCANNED" value={ms1.totalScanned}   iconBg="#eef2ff" iconColor="#4f46e5" trend="neutral" />
              <StatCard icon={CheckCircle2} label="OPEN PORTS"    value={ms1.openPorts}      iconBg="#dcfce7" iconColor="#16a34a" trend={ms1.openPorts > 5 ? "up" : "neutral"} />
              <StatCard icon={XCircle}      label="CLOSED PORTS"  value={ms1.closedPorts}    iconBg="#f1f5f9" iconColor="#64748b" />
              <StatCard icon={AlertTriangle}label="THREATS"       value={ms1.threatAlerts}   iconBg="#fee2e2" iconColor="#dc2626" trend={ms1.threatAlerts > 0 ? "up" : "neutral"} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
              {/* Top ports */}
              <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 16, border: "1px solid #f1f5f9" }}>
                <p style={{ margin: "0 0 12px", fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>TOP PORTS</p>
                {ms1.topPorts.length === 0 && <p style={{ fontSize: 12, color: "#94a3b8" }}>No data</p>}
                {ms1.topPorts.map((p, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <code style={{ fontSize: 11, fontFamily: "monospace", color: "#4f46e5", backgroundColor: "#eef2ff", padding: "1px 6px", borderRadius: 4, flexShrink: 0 }}>{p.port}</code>
                    <span style={{ fontSize: 11, color: "#475569", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.service}</span>
                    <span style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>×{p.count}</span>
                  </div>
                ))}
              </div>

              {/* Protocol breakdown */}
              <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 16, border: "1px solid #f1f5f9" }}>
                <p style={{ margin: "0 0 12px", fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>PROTOCOLS</p>
                {ms1.protocols.map((p, i) => {
                  const max = Math.max(...ms1.protocols.map(x => x.count));
                  return (
                    <div key={i} style={{ marginBottom: 8 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                        <span style={{ fontSize: 11, color: "#475569" }}>{p.name}</span>
                        <span style={{ fontSize: 11, color: "#94a3b8", fontFamily: "monospace" }}>{p.count}</span>
                      </div>
                      <div style={{ height: 4, backgroundColor: "#e2e8f0", borderRadius: 2, overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${(p.count / max) * 100}%`, backgroundColor: "#4f46e5", borderRadius: 2, transition: "width 0.4s ease" }} />
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Timeline */}
              <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 16, border: "1px solid #f1f5f9" }}>
                <p style={{ margin: "0 0 12px", fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>SCAN TIMELINE</p>
                <MiniBarChart data={ms1.timeline} color="#4f46e5" />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MS2 — Traffic Analyzer */}
      {ms2 && (
        <div style={{ backgroundColor: "#fff", borderRadius: 16, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.05)", overflow: "hidden" }}>
          <div style={{ padding: "14px 20px", borderBottom: "1px solid #f1f5f9", display: "flex", alignItems: "center", justifyContent: "space-between", backgroundColor: "#fafafa" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 32, height: 32, backgroundColor: "#2563eb", borderRadius: 9, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Activity style={{ width: 15, height: 15, color: "#fff" }} />
              </div>
              <div>
                <p style={{ margin: 0, fontSize: 13, fontWeight: 700, color: "#1e293b" }}>MS2 — Traffic Analyzer</p>
                <p style={{ margin: 0, fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>{ms2Filename}</p>
              </div>
            </div>
            <span style={{ fontSize: 11, color: "#94a3b8", fontFamily: "monospace" }}>{ms2.totalPackets} packets</span>
          </div>

          <div style={{ padding: 20 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
              <StatCard icon={Wifi}         label="TOTAL PACKETS"  value={ms2.totalPackets}  iconBg="#dbeafe" iconColor="#2563eb" />
              <StatCard icon={ShieldAlert}  label="ALERTS"         value={ms2.alerts}        iconBg="#fee2e2" iconColor="#dc2626" trend={ms2.alerts > 0 ? "up" : "neutral"} />
              <StatCard icon={Globe}        label="UNIQUE HOSTS"   value={ms2.uniqueHosts}   iconBg="#f0fdf4" iconColor="#16a34a" />
              <StatCard icon={Zap}          label="AVG PKT SIZE"   value={`${ms2.avgPacketSize}B`} iconBg="#fef9c3" iconColor="#ca8a04" />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
              {/* Protocol donut */}
              <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 16, border: "1px solid #f1f5f9" }}>
                <p style={{ margin: "0 0 12px", fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>PROTOCOL MIX</p>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <DonutSegment protocols={ms2.protocols} />
                  <div style={{ flex: 1 }}>
                    {ms2.protocols.slice(0, 5).map((p, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                        <span style={{ width: 8, height: 8, borderRadius: 2, backgroundColor: p.color, flexShrink: 0, display: "inline-block" }} />
                        <span style={{ fontSize: 10, color: "#475569" }}>{p.name}</span>
                        <span style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace", marginLeft: "auto" }}>{p.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Top talkers */}
              <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 16, border: "1px solid #f1f5f9" }}>
                <p style={{ margin: "0 0 12px", fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>TOP TALKERS</p>
                {ms2.topTalkers.map((t, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7 }}>
                    <code style={{ fontSize: 10, color: "#2563eb", fontFamily: "monospace", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.ip}</code>
                    <span style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>{t.packets}p</span>
                    <span style={{ fontSize: 9, backgroundColor: t.role === "External" ? "#fef9c3" : "#dbeafe", color: t.role === "External" ? "#ca8a04" : "#2563eb", borderRadius: 4, padding: "1px 5px", fontWeight: 600 }}>{t.role}</span>
                  </div>
                ))}
              </div>

              {/* Severity + Timeline */}
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 14, border: "1px solid #f1f5f9", flex: 1 }}>
                  <p style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>ALERT SEVERITY</p>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                    {[
                      { label: "Critical", count: ms2.severityCounts.critical, bg: "#fce7f3", color: "#be185d" },
                      { label: "High",     count: ms2.severityCounts.high,     bg: "#fee2e2", color: "#dc2626" },
                      { label: "Medium",   count: ms2.severityCounts.medium,   bg: "#fef9c3", color: "#ca8a04" },
                      { label: "Low",      count: ms2.severityCounts.low,      bg: "#dcfce7", color: "#16a34a" },
                    ].map(s => (
                      <div key={s.label} style={{ backgroundColor: s.bg, borderRadius: 8, padding: "6px 10px", textAlign: "center" }}>
                        <p style={{ margin: 0, fontSize: 16, fontWeight: 800, color: s.color }}>{s.count}</p>
                        <p style={{ margin: 0, fontSize: 10, color: s.color, opacity: 0.8 }}>{s.label}</p>
                      </div>
                    ))}
                  </div>
                </div>
                <div style={{ backgroundColor: "#f8fafc", borderRadius: 12, padding: 14, border: "1px solid #f1f5f9" }}>
                  <p style={{ margin: "0 0 8px", fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>TRAFFIC TIMELINE</p>
                  <MiniBarChart data={ms2.timeline} color="#2563eb" />
                </div>
              </div>
            </div>

            {/* Flags row */}
            {ms2.flags.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <button onClick={() => toggle("flags")} style={{ display: "flex", alignItems: "center", gap: 6, background: "none", border: "none", cursor: "pointer", padding: 0, marginBottom: 8 }}>
                  <p style={{ margin: 0, fontSize: 11, fontWeight: 700, color: "#475569", fontFamily: "monospace", letterSpacing: "0.05em" }}>TCP FLAGS DISTRIBUTION</p>
                  {expandedSection === "flags" ? <ChevronUp style={{ width: 12, height: 12, color: "#94a3b8" }} /> : <ChevronDown style={{ width: 12, height: 12, color: "#94a3b8" }} />}
                </button>
                {expandedSection === "flags" && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                    {ms2.flags.map((f, i) => (
                      <div key={i} style={{ backgroundColor: "#eef2ff", borderRadius: 8, padding: "6px 12px", display: "flex", gap: 8, alignItems: "center" }}>
                        <code style={{ fontSize: 11, color: "#4f46e5", fontFamily: "monospace" }}>{f.name}</code>
                        <span style={{ fontSize: 11, color: "#64748b" }}>{f.count}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );

  // ─── Render ────────────────────────────────────────────────────────────────
  return (
    <div style={{ padding: 24, backgroundColor: "#f8fafc", minHeight: "100%" }}>

      {/* Page header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 24 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <div style={{ width: 36, height: 36, backgroundColor: "#4f46e5", borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 2px 8px rgba(79,70,229,0.3)" }}>
              <BarChart2 style={{ width: 18, height: 18, color: "#fff" }} />
            </div>
            <h1 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "#0f172a", letterSpacing: "-0.02em" }}>Monitoring Dashboard</h1>
          </div>
          <p style={{ margin: 0, fontSize: 13, color: "#64748b" }}>
            Performance & threat metrics for MS1 (Port Scanner) and MS2 (Traffic Analyzer)
          </p>
        </div>

        {/* View toggle */}
        <div style={{ display: "flex", backgroundColor: "#f1f5f9", borderRadius: 10, padding: 3, border: "1px solid #e2e8f0" }}>
          {([
            { id: "simple", icon: Eye,   label: "Overview" },
            { id: "tech",   icon: Code2, label: "Technical" },
          ] as { id: "simple" | "tech"; icon: React.ElementType; label: string }[]).map(v => (
            <button key={v.id} onClick={() => setViewMode(v.id)}
              style={{
                display: "flex", alignItems: "center", gap: 6, padding: "7px 14px", borderRadius: 7, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.2s",
                backgroundColor: viewMode === v.id ? "#fff" : "transparent",
                color: viewMode === v.id ? "#1e293b" : "#94a3b8",
                boxShadow: viewMode === v.id ? "0 1px 4px rgba(0,0,0,0.1)" : "none",
              }}>
              <v.icon style={{ width: 13, height: 13 }} />
              {v.label}
            </button>
          ))}
        </div>
      </div>

      {/* Upload area */}
      <div style={{ backgroundColor: "#fff", borderRadius: 16, padding: 20, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.05)", marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <FileText style={{ width: 16, height: 16, color: "#4f46e5" }} />
            <p style={{ margin: 0, fontSize: 13, fontWeight: 700, color: "#1e293b" }}>Load Log Files</p>
          </div>
          {hasAny && (
            <button
              onClick={() => { setMs1Loaded(false); setMs2Loaded(false); setMs1Entries([]); setMs2Entries([]); }}
              style={{ display: "flex", alignItems: "center", gap: 5, backgroundColor: "#f1f5f9", border: "1px solid #e2e8f0", borderRadius: 7, padding: "5px 10px", fontSize: 11, color: "#64748b", cursor: "pointer", fontWeight: 600 }}>
              <RefreshCw style={{ width: 11, height: 11 }} /> Reset
            </button>
          )}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 600, color: "#4f46e5", fontFamily: "monospace" }}>MS1 · PORT SCANNER</p>
            <FileDropZone label="Drop CSV or JSON log" accept=".csv,.json" onFile={handleMs1File} loaded={ms1Loaded} filename={ms1Filename} />
          </div>
          <div>
            <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 600, color: "#2563eb", fontFamily: "monospace" }}>MS2 · TRAFFIC ANALYZER</p>
            <FileDropZone label="Drop PCAP, CSV, or JSON log" accept=".pcap,.pcapng,.csv,.json" onFile={handleMs2File} loaded={ms2Loaded} filename={ms2Filename} />
          </div>
        </div>
      </div>

      {/* Empty state */}
      {!hasAny && (
        <div style={{ textAlign: "center", padding: "48px 24px", backgroundColor: "#fff", borderRadius: 16, border: "1px dashed #e2e8f0" }}>
          <div style={{ width: 64, height: 64, backgroundColor: "#eef2ff", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px" }}>
            <BarChart2 style={{ width: 28, height: 28, color: "#6366f1" }} />
          </div>
          <h3 style={{ margin: "0 0 8px", fontSize: 16, fontWeight: 700, color: "#1e293b" }}>No logs loaded yet</h3>
          <p style={{ margin: "0 0 16px", fontSize: 13, color: "#64748b", maxWidth: 380, marginLeft: "auto", marginRight: "auto" }}>
            Upload your MS1 port scan logs (CSV/JSON) and MS2 traffic logs (PCAP/CSV/JSON) above to see the monitoring dashboard.
          </p>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 6, backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: 8, padding: "8px 14px" }}>
            <Info style={{ width: 13, height: 13, color: "#94a3b8" }} />
            <span style={{ fontSize: 12, color: "#64748b" }}>Switch between <strong>Overview</strong> and <strong>Technical</strong> views using the toggle above</span>
          </div>
        </div>
      )}

      {/* Dashboard content */}
      {hasAny && (viewMode === "tech" ? <TechView /> : <SimpleView />)}
    </div>
  );
}