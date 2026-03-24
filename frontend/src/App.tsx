import { useState } from "react";
import { PasswordStrength } from "./components/PasswordStrength";
import { PasswordGenerator } from "./components/PasswordGenerator";
import { InputValidator } from "./components/InputValidator";
import { PortScanner } from "./components/PortScanner";
import { TrafficAnalyzer } from "./components/TrafficAnalyzer";
import { BreachChecker } from "./components/BreachChecker";          // ← ADD
import {
  Shield, Zap, ScanEye, Radar, Activity,
  PanelLeftClose, PanelLeftOpen, ChevronDown, ChevronRight,
  Lock, Network, ArrowRight, KeyRound, FileCheck,
  CheckCircle2, Info, ShieldAlert,                                   // ← ADD ShieldAlert
} from "lucide-react";

// ── 1. Add "breach" to the union ─────────────────────────────────────────────
type TabId = "home" | "strength" | "generator" | "validator" | "scanner" | "traffic" | "breach";

const C: Record<string, { dot: string; active: string; icon: string; bar: string }> = {
  blue:    { dot: "bg-blue-500",    active: "text-blue-700 bg-blue-50 border-blue-200",          icon: "text-blue-600",    bar: "bg-blue-500"    },
  indigo:  { dot: "bg-indigo-500",  active: "text-indigo-700 bg-indigo-50 border-indigo-200",    icon: "text-indigo-600",  bar: "bg-indigo-500"  },
  violet:  { dot: "bg-violet-500",  active: "text-violet-700 bg-violet-50 border-violet-200",    icon: "text-violet-600",  bar: "bg-violet-500"  },
  emerald: { dot: "bg-emerald-500", active: "text-emerald-700 bg-emerald-50 border-emerald-200", icon: "text-emerald-600", bar: "bg-emerald-500" },
  amber:   { dot: "bg-amber-500",   active: "text-amber-700 bg-amber-50 border-amber-200",       icon: "text-amber-600",   bar: "bg-amber-500"   },
  rose:    { dot: "bg-rose-500",    active: "text-rose-700 bg-rose-50 border-rose-200",          icon: "text-rose-600",    bar: "bg-rose-500"    },
  red:     { dot: "bg-red-500",     active: "text-red-700 bg-red-50 border-red-200",             icon: "text-red-600",     bar: "bg-red-500"     }, // ← ADD
};

// ── 2. Add breach entry to MS1_TOOLS ─────────────────────────────────────────
const MS1_TOOLS = [
  { id: "strength"  as TabId, icon: ScanEye,     title: "Analyze",  subtitle: "Password strength", color: "blue"   },
  { id: "generator" as TabId, icon: Zap,         title: "Generate", subtitle: "Secure password",   color: "indigo" },
  { id: "validator" as TabId, icon: Shield,      title: "Validate", subtitle: "Form inputs",       color: "violet" },
  { id: "breach"    as TabId, icon: ShieldAlert, title: "Breach",   subtitle: "Leak checker",      color: "red"    }, // ← ADD
];
const MS2_TOOLS = [
  { id: "scanner" as TabId, icon: Radar,    title: "Scanner", subtitle: "Port scanning",    color: "emerald" },
  { id: "traffic" as TabId, icon: Activity, title: "Traffic", subtitle: "Network analysis", color: "rose"    },
];

export default function App() {
  const [activeTab,        setActiveTab]        = useState<TabId>("home");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [ms1Open,          setMs1Open]          = useState(true);
  const [ms2Open,          setMs2Open]          = useState(true);

  const isHome      = activeTab === "home";
  const showSidebar = !isHome;

  // ── 3. Add "breach" to the ms1Open guard ─────────────────────────────────
  const navigate = (tab: TabId) => {
    setActiveTab(tab);
    if (["strength", "generator", "validator", "breach"].includes(tab)) setMs1Open(true);
    if (["scanner", "traffic"].includes(tab))                           setMs2Open(true);
  };

  const NavItem = ({ tool }: { tool: (typeof MS1_TOOLS)[0] }) => {
    const isActive = activeTab === tool.id;
    const c = C[tool.color];
    return (
      <button
        onClick={() => navigate(tool.id)}
        title={sidebarCollapsed ? tool.title : ""}
        className={`w-full group relative flex items-center gap-3 px-3 py-2.5 rounded-xl border transition-all duration-200 text-left
          ${isActive
            ? `${c.active} border shadow-sm`
            : "border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50 hover:border-slate-200"}`}
      >
        {isActive && <div className={`absolute left-0 top-2 bottom-2 w-[3px] rounded-r-full ${c.bar}`} />}
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 transition-all
          ${isActive ? "bg-white shadow-sm" : "bg-slate-100 group-hover:bg-white"}`}>
          <tool.icon className={`w-3.5 h-3.5 ${isActive ? c.icon : "text-slate-400 group-hover:text-slate-600"}`} />
        </div>
        {!sidebarCollapsed && (
          <div className="min-w-0">
            <p className="text-xs font-semibold truncate leading-none mb-0.5">{tool.title}</p>
            <p className="text-[10px] font-mono truncate opacity-60">{tool.subtitle}</p>
          </div>
        )}
      </button>
    );
  };

  const NavGroup = ({
    label, sublabel, dotColor, open, onToggle, tools,
  }: {
    label: string; sublabel: string; dotColor: string;
    open: boolean; onToggle: () => void; tools: (typeof MS1_TOOLS);
  }) => (
    <div>
      <button
        onClick={onToggle}
        title={sidebarCollapsed ? label : ""}
        className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg hover:bg-slate-50 transition-all"
      >
        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${dotColor}`} />
        {!sidebarCollapsed && (
          <>
            <div className="flex-1 text-left min-w-0">
              <p className="text-[11px] font-bold text-slate-700 truncate leading-none mb-0.5">{label}</p>
              <p className="text-[9px] text-slate-400 font-mono truncate">{sublabel}</p>
            </div>
            {open
              ? <ChevronDown  className="w-3 h-3 text-slate-300 flex-shrink-0" />
              : <ChevronRight className="w-3 h-3 text-slate-300 flex-shrink-0" />}
          </>
        )}
      </button>
      {(open || sidebarCollapsed) && (
        <div className={`mt-1 space-y-0.5 ${!sidebarCollapsed ? "ml-2 pl-3 border-l-2 border-slate-100" : ""}`}>
          {tools.map(t => <NavItem key={t.id} tool={t} />)}
        </div>
      )}
    </div>
  );

  // ── Home page ─────────────────────────────────────────────
  const HomePage = () => (
    <div style={{ backgroundColor: "#eef2f7", minHeight: "100%", padding: "32px" }}>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, marginBottom: 20 }}>
        <Shield style={{ width: 26, height: 26, color: "#4f46e5" }} strokeWidth={1.5} />
        <span style={{ fontSize: 20, fontWeight: 700, color: "#1e293b" }}>Web Security Toolkit</span>
      </div>

      <div style={{ textAlign: "center", marginBottom: 32 }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 12 }}>
          <Shield style={{ width: 56, height: 56, color: "#6366f1" }} strokeWidth={1.2} />
        </div>
        <h2 style={{ fontSize: 22, fontWeight: 700, color: "#1e293b", margin: "0 0 10px" }}>
          Welcome to Your Security Toolkit
        </h2>
        <p style={{ fontSize: 14, color: "#64748b", maxWidth: 520, margin: "0 auto", lineHeight: 1.6 }}>
          Everything you need to protect your accounts and understand your network - all running safely in your browser
        </p>
      </div>

      {/* Tool cards */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 24 }}>

        <div style={{ backgroundColor: "#fff", borderRadius: 16, padding: 24, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.06)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 44, height: 44, backgroundColor: "#4f46e5", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 4px 12px rgba(79,70,229,0.25)" }}>
              <Shield style={{ width: 22, height: 22, color: "#fff" }} />
            </div>
            <span style={{ fontSize: 16, fontWeight: 700, color: "#1e293b" }}>Security Tools</span>
          </div>
          <p style={{ fontSize: 13, color: "#64748b", marginBottom: 16, lineHeight: 1.5 }}>
            Protect your accounts with password management and input validation tools
          </p>
          <div style={{ marginBottom: 20 }}>
            {[
              { icon: Lock,        label: "Check password strength",            tab: "strength"  as TabId },
              { icon: Zap,         label: "Generate secure passwords",           tab: "generator" as TabId },
              { icon: FileCheck,   label: "Validate and sanitize inputs",        tab: "validator" as TabId },
              { icon: ShieldAlert, label: "Check for leaked passwords & emails", tab: "breach"    as TabId }, // ← ADD
              { icon: Shield,      label: "Security testing terminal",           tab: "validator" as TabId },
            ].map(item => (
              <button key={item.label} onClick={() => navigate(item.tab)}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", background: "none", border: "none", cursor: "pointer", padding: "6px 0", color: "#475569", fontSize: 13, textAlign: "left" }}
                onMouseEnter={e => (e.currentTarget.style.color = "#4f46e5")}
                onMouseLeave={e => (e.currentTarget.style.color = "#475569")}
              >
                <item.icon style={{ width: 15, height: 15, color: "#6366f1", flexShrink: 0 }} />
                {item.label}
              </button>
            ))}
          </div>
          <button onClick={() => navigate("strength")}
            style={{ width: "100%", backgroundColor: "#4f46e5", color: "#fff", border: "none", borderRadius: 12, padding: "13px 0", fontWeight: 600, fontSize: 14, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}
            onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#4338ca")}
            onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#4f46e5")}
          >
            Open Security Tools <ArrowRight style={{ width: 16, height: 16 }} />
          </button>
        </div>

        <div style={{ backgroundColor: "#fff", borderRadius: 16, padding: 24, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.06)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 44, height: 44, backgroundColor: "#2563eb", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, boxShadow: "0 4px 12px rgba(37,99,235,0.25)" }}>
              <Network style={{ width: 22, height: 22, color: "#fff" }} />
            </div>
            <span style={{ fontSize: 16, fontWeight: 700, color: "#1e293b" }}>Network Tools</span>
          </div>
          <p style={{ fontSize: 13, color: "#64748b", marginBottom: 16, lineHeight: 1.5 }}>
            Explore how networks work with educational simulation tools
          </p>
          <div style={{ marginBottom: 20 }}>
            {[
              { icon: Radar,    label: "Scan network ports",      tab: "scanner" as TabId },
              { icon: Activity, label: "Analyze network traffic",  tab: "traffic" as TabId },
              { icon: Activity, label: "Learn about protocols",    tab: "traffic" as TabId },
            ].map(item => (
              <button key={item.label} onClick={() => navigate(item.tab)}
                style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", background: "none", border: "none", cursor: "pointer", padding: "6px 0", color: "#475569", fontSize: 13, textAlign: "left" }}
                onMouseEnter={e => (e.currentTarget.style.color = "#2563eb")}
                onMouseLeave={e => (e.currentTarget.style.color = "#475569")}
              >
                <item.icon style={{ width: 15, height: 15, color: "#3b82f6", flexShrink: 0 }} />
                {item.label}
              </button>
            ))}
          </div>
          <button onClick={() => navigate("scanner")}
            style={{ width: "100%", backgroundColor: "#2563eb", color: "#fff", border: "none", borderRadius: 12, padding: "13px 0", fontWeight: 600, fontSize: 14, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}
            onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#1d4ed8")}
            onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#2563eb")}
          >
            Open Network Tools <ArrowRight style={{ width: 16, height: 16 }} />
          </button>
        </div>
      </div>

      {/* Feature pills */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, marginBottom: 24 }}>
        {[
          { iconEl: <CheckCircle2 style={{ width: 24, height: 24, color: "#16a34a" }} />, bg: "#dcfce7", title: "Python Powered",  desc: "All processing runs on a FastAPI backend with real cryptographic functions." },
          { iconEl: <Zap          style={{ width: 24, height: 24, color: "#2563eb" }} />, bg: "#dbeafe", title: "Lightning Fast",   desc: "No waiting. Real-time results with a React frontend and Python backend."      },
          { iconEl: <Info         style={{ width: 24, height: 24, color: "#7c3aed" }} />, bg: "#ede9fe", title: "Easy to Learn",    desc: "Simple, friendly tools with clear explanations for every security concept."   },
        ].map(f => (
          <div key={f.title} style={{ backgroundColor: "#fff", borderRadius: 12, padding: 20, border: "1px solid #e2e8f0", boxShadow: "0 1px 3px rgba(0,0,0,0.05)", textAlign: "center" }}>
            <div style={{ width: 48, height: 48, backgroundColor: f.bg, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 12px" }}>
              {f.iconEl}
            </div>
            <p style={{ fontSize: 13, fontWeight: 600, color: "#1e293b", marginBottom: 6 }}>{f.title}</p>
            <p style={{ fontSize: 12, color: "#64748b", lineHeight: 1.5 }}>{f.desc}</p>
          </div>
        ))}
      </div>

      {/* About */}
      <div style={{ backgroundColor: "#fff", borderRadius: 12, padding: 20, border: "1px solid #e2e8f0", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
          <Info style={{ width: 16, height: 16, color: "#4f46e5" }} />
          <span style={{ fontSize: 13, fontWeight: 600, color: "#1e293b" }}>About This Toolkit</span>
        </div>
        <p style={{ fontSize: 12, color: "#64748b", lineHeight: 1.6, margin: 0 }}>
          This toolkit combines practical security tools with educational network simulations.
          The security tools use real cryptographic functions (bcrypt, SHA-256) to help manage passwords
          and validate data. The network tools use Python's socket library and Scapy for real TCP port
          scanning and packet analysis, falling back to simulation when elevated privileges are unavailable.
        </p>
        <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid #f1f5f9" }}>
          <p style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace", marginBottom: 8 }}>
            Group 4 · MO-IT142 Security Script Programming · Terminal Assessment AY 2024-2025
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {["FastAPI", "React + TypeScript", "Python 3", "Scapy", "bcrypt", "Tailwind CSS", "Render", "HIBP API"].map(tag => (
              <span key={tag} style={{ fontSize: 10, fontFamily: "monospace", backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", color: "#64748b", borderRadius: 999, padding: "2px 8px" }}>
                {tag}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  // ── App shell ─────────────────────────────────────────────
  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#f8fafc", display: "flex", flexDirection: "column" }}>

      {/* Top bar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 20px", flexShrink: 0 }}>
        <button
          onClick={() => setActiveTab("home")}
          style={{ display: "flex", alignItems: "center", gap: 12, background: "none", border: "none", cursor: "pointer" }}
        >
          <div style={{ width: 32, height: 32, backgroundColor: "#4f46e5", borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 2px 8px rgba(79,70,229,0.3)" }}>
            <KeyRound style={{ width: 16, height: 16, color: "#fff" }} />
          </div>
          <div style={{ textAlign: "left" }}>
            <p style={{ margin: 0, fontSize: 13, fontWeight: 900, color: "#0f172a", letterSpacing: "-0.02em", lineHeight: 1 }}>SecureKit</p>
            <p style={{ margin: 0, fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>Multi-Function Security Tool</p>
          </div>
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {isHome && (
            <button
              onClick={() => navigate("strength")}
              style={{ display: "flex", alignItems: "center", gap: 6, backgroundColor: "#4f46e5", color: "#fff", border: "none", borderRadius: 8, padding: "7px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}
              onMouseEnter={e => (e.currentTarget.style.backgroundColor = "#4338ca")}
              onMouseLeave={e => (e.currentTarget.style.backgroundColor = "#4f46e5")}
            >
              <Lock style={{ width: 13, height: 13 }} />
              Open Tools
            </button>
          )}

          {!isHome && (
            <button
              onClick={() => setSidebarCollapsed(s => !s)}
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              style={{ display: "flex", alignItems: "center", gap: 6, backgroundColor: "#f1f5f9", border: "1px solid #e2e8f0", borderRadius: 8, padding: "6px 12px", fontSize: 12, fontWeight: 600, color: "#475569", cursor: "pointer" }}
            >
              {sidebarCollapsed
                ? <PanelLeftOpen  style={{ width: 15, height: 15 }} />
                : <PanelLeftClose style={{ width: 15, height: 15 }} />}
              {sidebarCollapsed ? "Expand" : "Collapse"}
            </button>
          )}

          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ fontSize: 12, color: "#94a3b8", fontFamily: "monospace" }}>v2.0 · MO-IT142</span>
          </div>
        </div>
      </div>

      {/* Body */}
      <div style={{ display: "flex", gap: 12, flex: 1, padding: "0 8px 8px", minHeight: 0 }}>

        {showSidebar && (
          <div style={{ width: sidebarCollapsed ? 56 : 210, flexShrink: 0, transition: "width 0.3s" }}>
            <div style={{ height: "100%", display: "flex", flexDirection: "column", backgroundColor: "#fff", borderRadius: 16, padding: 10, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.05)", gap: 4, overflowY: "auto" }}>

              <button
                onClick={() => setActiveTab("home")}
                title={sidebarCollapsed ? "Home" : ""}
                style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 12px", borderRadius: 12, border: "none", cursor: "pointer", fontWeight: 600, fontSize: 12, backgroundColor: "transparent", color: "#64748b", transition: "all 0.2s" }}
                onMouseEnter={e => { e.currentTarget.style.backgroundColor = "#f8fafc"; e.currentTarget.style.color = "#1e293b"; }}
                onMouseLeave={e => { e.currentTarget.style.backgroundColor = "transparent"; e.currentTarget.style.color = "#64748b"; }}
              >
                <div style={{ width: 28, height: 28, borderRadius: 8, backgroundColor: "#f1f5f9", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <Lock style={{ width: 14, height: 14, color: "#94a3b8" }} />
                </div>
                {!sidebarCollapsed && <span>Home</span>}
              </button>

              <div style={{ borderTop: "1px solid #f1f5f9", margin: "4px 0" }} />

              <NavGroup label="Milestone 1" sublabel="Web Security"     dotColor="bg-blue-500"   open={ms1Open} onToggle={() => setMs1Open(o => !o)}  tools={MS1_TOOLS} />
              <div style={{ borderTop: "1px solid #f1f5f9", margin: "4px 0" }} />
              <NavGroup label="Milestone 2" sublabel="Network Security" dotColor="bg-violet-500" open={ms2Open} onToggle={() => setMs2Open(o => !o)} tools={MS2_TOOLS} />
            </div>
          </div>
        )}

        {/* Content ── 4. Add breach render ──────────────────────────────── */}
        <div style={{ flex: 1, borderRadius: 16, border: "1px solid #e2e8f0", boxShadow: "0 1px 4px rgba(0,0,0,0.05)", overflow: "auto", backgroundColor: isHome ? "#eef2f7" : "#fff" }}>
          {activeTab === "home"      && <HomePage />}
          {activeTab === "strength"  && <div style={{ padding: 20 }}><PasswordStrength /></div>}
          {activeTab === "generator" && <div style={{ padding: 20 }}><PasswordGenerator /></div>}
          {activeTab === "validator" && <div style={{ padding: 20 }}><InputValidator /></div>}
          {activeTab === "scanner"   && <div style={{ padding: 20 }}><PortScanner /></div>}
          {activeTab === "traffic"   && <div style={{ padding: 20 }}><TrafficAnalyzer /></div>}
          {activeTab === "breach"    && <div style={{ padding: 20 }}><BreachChecker /></div>}  {/* ← ADD */}
        </div>
      </div>

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "6px 0 10px", flexShrink: 0 }}>
        <p style={{ fontSize: 11, color: "#94a3b8", fontFamily: "monospace", margin: 0 }}>
          Group 4 · MO-IT142 · Security Script Programming
        </p>
      </div>

      {/* User Guide — fixed bottom-left button */}
      <a
        href="/user-guide.html"
        target="_blank"
        rel="noopener noreferrer"
        style={{
          position: "fixed",
          bottom: 20,
          left: 20,
          zIndex: 9999,
          display: "flex",
          alignItems: "center",
          gap: 8,
          backgroundColor: "#4f46e5",
          color: "#fff",
          border: "none",
          borderRadius: 999,
          padding: "10px 18px",
          fontSize: 13,
          fontWeight: 600,
          textDecoration: "none",
          boxShadow: "0 4px 14px rgba(79,70,229,0.35)",
          cursor: "pointer",
          transition: "background-color 0.2s, box-shadow 0.2s",
        }}
        onMouseEnter={e => {
          (e.currentTarget as HTMLAnchorElement).style.backgroundColor = "#4338ca";
          (e.currentTarget as HTMLAnchorElement).style.boxShadow = "0 6px 20px rgba(79,70,229,0.45)";
        }}
        onMouseLeave={e => {
          (e.currentTarget as HTMLAnchorElement).style.backgroundColor = "#4f46e5";
          (e.currentTarget as HTMLAnchorElement).style.boxShadow = "0 4px 14px rgba(79,70,229,0.35)";
        }}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{ flexShrink: 0 }}
        >
          <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" />
          <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" />
        </svg>
        User Guide
      </a>
    </div>
  );
}