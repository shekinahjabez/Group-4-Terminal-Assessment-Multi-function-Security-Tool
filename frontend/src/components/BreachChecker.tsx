import { useState } from "react";
import { ShieldAlert, ShieldCheck, Eye, EyeOff, AlertCircle, Loader2, Lock, Mail, ExternalLink } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

type CheckTab = "password" | "email";

interface PwnedPasswordResult {
  found: boolean;
  count: number;
  hash:  string;
}

// XposedOrNot free /v1/check-email response:
// { "breaches": ["LinkedIn", "Adobe", ...], "BreachMetrics": {...} }
interface XonCheckEmailResponse {
  breaches?:      string[];   // array of breach names
  BreachMetrics?: {
    risk?: [string, number][]; // e.g. [["low", 2], ["high", 1]]
    year?: [string, number][]; // e.g. [["2012", 1], ["2019", 2]]
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────────

async function sha1(str: string): Promise<string> {
  const buf  = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function fmt(n: number): string { return Number(n).toLocaleString(); }

function severityFromCount(count: number) {
  if (count > 100_000) return { label: "Critical", color: "#b91c1c", bg: "#fef2f2", border: "#fecaca" };
  if (count > 10_000)  return { label: "High",     color: "#c2410c", bg: "#fff7ed", border: "#fed7aa" };
  if (count > 1_000)   return { label: "Medium",   color: "#a16207", bg: "#fefce8", border: "#fef08a" };
  return                      { label: "Low",      color: "#166534", bg: "#f0fdf4", border: "#bbf7d0" };
}

// ── Password check — HIBP Pwned Passwords (k-anonymity, always free) ──────────

async function checkPasswordBreach(password: string): Promise<PwnedPasswordResult> {
  const hash   = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res    = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!res.ok) throw new Error(`HIBP API error: ${res.status}`);
  const text   = await res.text();
  let count    = 0;
  for (const line of text.split("\r\n")) {
    const [s, c] = line.split(":");
    if (s === suffix) { count = parseInt(c, 10); break; }
  }
  return { found: count > 0, count, hash };
}

// ── Email check — XposedOrNot free API (breach names only, no key needed) ─────

async function checkEmailBreach(email: string): Promise<{ safe: boolean; breaches: string[]; metrics: XonCheckEmailResponse["BreachMetrics"] }> {
  const res = await fetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`);

  if (res.status === 404) return { safe: true, breaches: [], metrics: undefined };
  if (!res.ok) throw new Error(`XposedOrNot API error: ${res.status}`);

  const data: XonCheckEmailResponse = await res.json();
  const breaches = data.breaches ?? [];

  return { safe: breaches.length === 0, breaches, metrics: data.BreachMetrics };
}

// ── Component ──────────────────────────────────────────────────────────────────

export function BreachChecker() {
  const [tab,          setTab]          = useState<CheckTab>("password");

  // password tab
  const [password,     setPassword]     = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [pwLoading,    setPwLoading]    = useState(false);
  const [pwResult,     setPwResult]     = useState<PwnedPasswordResult | null>(null);
  const [pwError,      setPwError]      = useState<string | null>(null);
  const [pwEmpty,      setPwEmpty]      = useState(false);

  // email tab
  const [email,        setEmail]        = useState("");
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailSafe,    setEmailSafe]    = useState(false);
  const [emailBreaches,setEmailBreaches]= useState<string[]>([]);
  const [emailMetrics, setEmailMetrics] = useState<XonCheckEmailResponse["BreachMetrics"]>(undefined);
  const [emailFound,   setEmailFound]   = useState(false);
  const [emailError,   setEmailError]   = useState<string | null>(null);
  const [emailEmpty,   setEmailEmpty]   = useState(false);

  // ── Handlers ───────────────────────────────────────────────────────────────

  const handlePasswordCheck = async () => {
    if (!password.trim()) { setPwEmpty(true); setPwResult(null); setPwError(null); return; }
    setPwEmpty(false); setPwError(null); setPwResult(null); setPwLoading(true);
    try {
      setPwResult(await checkPasswordBreach(password));
    } catch (err) {
      setPwError(err instanceof Error ? err.message : "Network error. Please try again.");
    } finally {
      setPwLoading(false);
    }
  };

  const handleEmailCheck = async () => {
    if (!email.trim()) { setEmailEmpty(true); setEmailFound(false); setEmailSafe(false); setEmailError(null); return; }
    setEmailEmpty(false); setEmailError(null); setEmailFound(false);
    setEmailSafe(false); setEmailBreaches([]); setEmailMetrics(undefined); setEmailLoading(true);
    try {
      const { safe, breaches, metrics } = await checkEmailBreach(email.trim());
      if (safe) {
        setEmailSafe(true);
      } else {
        setEmailFound(true);
        setEmailBreaches(breaches);
        setEmailMetrics(metrics);
      }
    } catch (err) {
      setEmailError(err instanceof Error ? err.message : "Network error. Please try again.");
    } finally {
      setEmailLoading(false);
    }
  };

  // ── Shared styles ───────────────────────────────────────────────────────────

  const inputStyle: React.CSSProperties = {
    width: "100%", padding: "9px 12px",
    border: "2px solid #e2e8f0", borderRadius: 8,
    fontSize: 13, color: "#1e293b", backgroundColor: "#fff",
    outline: "none", boxSizing: "border-box",
  };

  const primaryBtn = (disabled: boolean): React.CSSProperties => ({
    width: "100%", padding: "12px 0", borderRadius: 10,
    border: "none", cursor: disabled ? "not-allowed" : "pointer",
    backgroundColor: disabled ? "#cbd5e1" : "#4f46e5",
    color: "#fff", fontWeight: 600, fontSize: 14,
    display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
    transition: "background-color 0.2s",
  });

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* Header */}
      <div>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "#1e293b", margin: 0 }}>
          Leaked Password &amp; Breach Checker
        </h2>
        <p style={{ fontSize: 12, color: "#64748b", margin: "4px 0 0" }}>
          Check if your password or email appeared in known data breaches
        </p>
      </div>

      {/* Privacy note */}
      <div style={{ backgroundColor: "#f0fdf4", border: "2px solid #bbf7d0", borderRadius: 10, padding: "10px 14px", display: "flex", alignItems: "center", gap: 10 }}>
        <Lock style={{ width: 15, height: 15, color: "#16a34a", flexShrink: 0 }} />
        <p style={{ margin: 0, fontSize: 12, color: "#166534", lineHeight: 1.5 }}>
          <strong>k-anonymity:</strong> Your password is never sent over the network. Only the first 5 characters of its SHA-1 hash are transmitted; matching is done locally in your browser.
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 8 }}>
        {(["password", "email"] as CheckTab[]).map(t => (
          <button key={t} onClick={() => setTab(t)}
            style={{
              flex: 1, padding: "9px 0", borderRadius: 10, fontSize: 13, fontWeight: 600, cursor: "pointer",
              border: tab === t ? "2px solid #4f46e5" : "2px solid #e2e8f0",
              backgroundColor: tab === t ? "#4f46e5" : "#fff",
              color: tab === t ? "#fff" : "#64748b",
              display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
              transition: "all 0.15s",
            }}
          >
            {t === "password"
              ? <><Lock style={{ width: 13, height: 13 }} />Password Check</>
              : <><Mail style={{ width: 13, height: 13 }} />Email / Username</>}
          </button>
        ))}
      </div>

      {/* ── PASSWORD TAB ── */}
      {tab === "password" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#475569", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Enter Password
            </label>
            <div style={{ position: "relative" }}>
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={e => { setPassword(e.target.value); setPwEmpty(false); setPwResult(null); setPwError(null); }}
                onKeyDown={e => e.key === "Enter" && handlePasswordCheck()}
                placeholder="Type your password here..."
                style={{ ...inputStyle, paddingRight: 44 }}
                onFocus={e  => (e.currentTarget.style.borderColor = "#4f46e5")}
                onBlur={e   => (e.currentTarget.style.borderColor = "#e2e8f0")}
              />
              <button type="button" onClick={() => setShowPassword(s => !s)}
                style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: "#94a3b8", padding: 2 }}
              >
                {showPassword ? <EyeOff style={{ width: 18, height: 18 }} /> : <Eye style={{ width: 18, height: 18 }} />}
              </button>
            </div>
          </div>

          <button onClick={handlePasswordCheck} disabled={pwLoading} style={primaryBtn(pwLoading)}
            onMouseEnter={e => { if (!pwLoading) e.currentTarget.style.backgroundColor = "#4338ca"; }}
            onMouseLeave={e => { if (!pwLoading) e.currentTarget.style.backgroundColor = "#4f46e5"; }}
          >
            {pwLoading
              ? <><Loader2 style={{ width: 16, height: 16, animation: "spin 0.7s linear infinite" }} />Checking...</>
              : <><ShieldAlert style={{ width: 16, height: 16 }} />Check Password</>}
          </button>

          {pwEmpty && (
            <div style={{ backgroundColor: "#fef2f2", borderLeft: "4px solid #ef4444", borderRadius: 8, padding: "10px 14px", display: "flex", alignItems: "center", gap: 10 }}>
              <AlertCircle style={{ width: 16, height: 16, color: "#dc2626", flexShrink: 0 }} />
              <span style={{ fontSize: 13, color: "#b91c1c", fontWeight: 500 }}>Please enter a password to check.</span>
            </div>
          )}

          {pwError && (
            <div style={{ backgroundColor: "#fef2f2", border: "2px solid #fecaca", borderRadius: 10, padding: "10px 14px", color: "#dc2626", fontSize: 12, display: "flex", gap: 8 }}>
              <span style={{ fontWeight: 700 }}>Error:</span><span>{pwError}</span>
            </div>
          )}

          {pwResult && (() => {
            const sev = pwResult.found ? severityFromCount(pwResult.count) : null;
            return pwResult.found ? (
              <div style={{ backgroundColor: sev!.bg, border: `2px solid ${sev!.border}`, borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 44, height: 44, backgroundColor: sev!.bg, border: `2px solid ${sev!.border}`, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <ShieldAlert style={{ width: 22, height: 22, color: sev!.color }} />
                  </div>
                  <div>
                    <p style={{ margin: 0, fontSize: 16, fontWeight: 700, color: sev!.color }}>Password Compromised</p>
                    <p style={{ margin: "2px 0 0", fontSize: 12, color: "#64748b" }}>
                      Found in <strong style={{ color: sev!.color }}>{fmt(pwResult.count)}</strong> breach record{pwResult.count !== 1 ? "s" : ""}
                    </p>
                  </div>
                  <span style={{ marginLeft: "auto", backgroundColor: sev!.bg, border: `1px solid ${sev!.border}`, color: sev!.color, borderRadius: 999, padding: "3px 12px", fontSize: 11, fontWeight: 700 }}>
                    {sev!.label} Risk
                  </span>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  {[{ label: "Exposures", value: fmt(pwResult.count) }, { label: "Risk Level", value: sev!.label }].map(s => (
                    <div key={s.label} style={{ backgroundColor: "#fff", border: "2px solid #e2e8f0", borderRadius: 10, padding: "10px 12px", textAlign: "center" }}>
                      <p style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>{s.label}</p>
                      <p style={{ fontSize: 14, fontWeight: 700, color: sev!.color, margin: "4px 0 0" }}>{s.value}</p>
                    </div>
                  ))}
                </div>

                <div style={{ backgroundColor: "#fff", border: "2px solid #e2e8f0", borderRadius: 10, padding: "12px 14px" }}>
                  <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em" }}>Recommendations</p>
                  <ul style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 4 }}>
                    {[
                      "Change this password immediately on all accounts where it is used.",
                      "Never reuse passwords — use a unique password for every account.",
                      "Use the Password Generator to create a strong replacement.",
                      pwResult.count > 100_000 ? "This is an extremely common password known to attackers." : null,
                    ].filter(Boolean).map((tip, i) => (
                      <li key={i} style={{ fontSize: 12, color: "#475569", lineHeight: 1.5 }}>{tip}</li>
                    ))}
                  </ul>
                </div>

                <div style={{ backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: 8, padding: "8px 12px" }}>
                  <p style={{ margin: 0, fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>
                    SHA-1: <span style={{ color: "#64748b" }}>{pwResult.hash.slice(0, 5)}</span>
                    <span style={{ color: "#cbd5e1" }}>{pwResult.hash.slice(5)}</span>
                    &nbsp;·&nbsp; Only the first 5 chars were transmitted
                  </p>
                </div>
              </div>
            ) : (
              <div style={{ backgroundColor: "#f0fdf4", border: "2px solid #bbf7d0", borderRadius: 12, padding: 20, display: "flex", alignItems: "center", gap: 14 }}>
                <div style={{ width: 44, height: 44, backgroundColor: "#dcfce7", border: "2px solid #86efac", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <ShieldCheck style={{ width: 22, height: 22, color: "#16a34a" }} />
                </div>
                <div>
                  <p style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#15803d" }}>Not Found in Breaches</p>
                  <p style={{ margin: "4px 0 0", fontSize: 12, color: "#166534", lineHeight: 1.5 }}>
                    This password was not found in any known breach database. Make sure it's also long and unique for best protection.
                  </p>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* ── EMAIL TAB ── */}
      {tab === "email" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

          {/* Source badge */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, backgroundColor: "#eff6ff", border: "2px solid #bfdbfe", borderRadius: 10, padding: "8px 14px" }}>
            <ShieldCheck style={{ width: 14, height: 14, color: "#3b82f6", flexShrink: 0 }} />
            <p style={{ margin: 0, fontSize: 11, color: "#1e40af", fontFamily: "monospace" }}>
              Powered by{" "}
              <a href="https://xposedornot.com" target="_blank" rel="noopener noreferrer" style={{ color: "#2563eb", fontWeight: 700 }}>
                XposedOrNot
              </a>
              {" "}— free, open-source breach API · no API key required
            </p>
          </div>

          {/* Input */}
          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#475569", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Email or Username
            </label>
            <input
              type="email"
              value={email}
              onChange={e => { setEmail(e.target.value); setEmailEmpty(false); setEmailFound(false); setEmailSafe(false); setEmailError(null); }}
              onKeyDown={e => e.key === "Enter" && handleEmailCheck()}
              placeholder="email@example.com"
              style={inputStyle}
              onFocus={e => (e.currentTarget.style.borderColor = "#4f46e5")}
              onBlur={e  => (e.currentTarget.style.borderColor = "#e2e8f0")}
            />
          </div>

          <button onClick={handleEmailCheck} disabled={emailLoading} style={primaryBtn(emailLoading)}
            onMouseEnter={e => { if (!emailLoading) e.currentTarget.style.backgroundColor = "#4338ca"; }}
            onMouseLeave={e => { if (!emailLoading) e.currentTarget.style.backgroundColor = "#4f46e5"; }}
          >
            {emailLoading
              ? <><Loader2 style={{ width: 16, height: 16, animation: "spin 0.7s linear infinite" }} />Checking...</>
              : <><ShieldAlert style={{ width: 16, height: 16 }} />Check Email</>}
          </button>

          {emailEmpty && (
            <div style={{ backgroundColor: "#fef2f2", borderLeft: "4px solid #ef4444", borderRadius: 8, padding: "10px 14px", display: "flex", alignItems: "center", gap: 10 }}>
              <AlertCircle style={{ width: 16, height: 16, color: "#dc2626", flexShrink: 0 }} />
              <span style={{ fontSize: 13, color: "#b91c1c", fontWeight: 500 }}>Please enter an email or username.</span>
            </div>
          )}

          {emailError && (
            <div style={{ backgroundColor: "#fef2f2", border: "2px solid #fecaca", borderRadius: 10, padding: "10px 14px", color: "#dc2626", fontSize: 12, display: "flex", gap: 8 }}>
              <span style={{ fontWeight: 700 }}>Error:</span><span>{emailError}</span>
            </div>
          )}

          {/* Safe */}
          {emailSafe && (
            <div style={{ backgroundColor: "#f0fdf4", border: "2px solid #bbf7d0", borderRadius: 12, padding: 20, display: "flex", alignItems: "center", gap: 14 }}>
              <div style={{ width: 44, height: 44, backgroundColor: "#dcfce7", border: "2px solid #86efac", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <ShieldCheck style={{ width: 22, height: 22, color: "#16a34a" }} />
              </div>
              <div>
                <p style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#15803d" }}>No Breaches Found</p>
                <p style={{ margin: "4px 0 0", fontSize: 12, color: "#166534", lineHeight: 1.5 }}>
                  <strong>{email}</strong> was not found in any known breach database.
                </p>
              </div>
            </div>
          )}

          {/* Breaches found */}
          {emailFound && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

              {/* Summary header */}
              <div style={{ backgroundColor: "#fef2f2", border: "2px solid #fecaca", borderRadius: 12, padding: 16, display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ width: 44, height: 44, backgroundColor: "#fee2e2", border: "2px solid #fca5a5", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <ShieldAlert style={{ width: 22, height: 22, color: "#dc2626" }} />
                </div>
                <div style={{ flex: 1 }}>
                  <p style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#b91c1c" }}>Email Found in Breaches</p>
                  <p style={{ margin: "2px 0 0", fontSize: 12, color: "#64748b" }}>
                    <strong style={{ color: "#b91c1c" }}>{email}</strong> appeared in{" "}
                    <strong style={{ color: "#b91c1c" }}>{emailBreaches.length}</strong> known breach{emailBreaches.length !== 1 ? "es" : ""}
                  </p>
                </div>
                <span style={{ backgroundColor: "#fee2e2", border: "1px solid #fca5a5", color: "#b91c1c", borderRadius: 999, padding: "3px 12px", fontSize: 11, fontWeight: 700, flexShrink: 0 }}>
                  {emailBreaches.length} breach{emailBreaches.length !== 1 ? "es" : ""}
                </span>
              </div>

              {/* Risk breakdown from metrics if available */}
              {emailMetrics?.risk && emailMetrics.risk.length > 0 && (
                <div style={{ display: "grid", gridTemplateColumns: `repeat(${Math.min(emailMetrics.risk.length, 4)}, 1fr)`, gap: 10 }}>
                  {emailMetrics.risk.map(([label, count]) => {
                    const colors: Record<string, { bg: string; border: string; text: string }> = {
                      low:      { bg: "#f0fdf4", border: "#bbf7d0", text: "#166534" },
                      moderate: { bg: "#fefce8", border: "#fef08a", text: "#a16207" },
                      high:     { bg: "#fff7ed", border: "#fed7aa", text: "#c2410c" },
                      critical: { bg: "#fef2f2", border: "#fecaca", text: "#b91c1c" },
                    };
                    const c = colors[label.toLowerCase()] ?? colors.moderate;
                    return (
                      <div key={label} style={{ backgroundColor: c.bg, border: `2px solid ${c.border}`, borderRadius: 10, padding: "10px 12px", textAlign: "center" }}>
                        <p style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>Risk: {label}</p>
                        <p style={{ fontSize: 16, fontWeight: 700, color: c.text, margin: "4px 0 0" }}>{count}</p>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Breach name pills */}
              {emailBreaches.length > 0 && (
                <div style={{ backgroundColor: "#fff", border: "2px solid #e2e8f0", borderRadius: 12, padding: 16 }}>
                  <p style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                    Breached Services ({emailBreaches.length})
                  </p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {emailBreaches.map(name => (
                      <span key={name} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 12, fontWeight: 600, backgroundColor: "#fef2f2", border: "1px solid #fecaca", color: "#b91c1c", borderRadius: 8, padding: "4px 10px" }}>
                        ⚠ {name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Year breakdown if available */}
              {emailMetrics?.year && emailMetrics.year.length > 0 && (
                <div style={{ backgroundColor: "#f8fafc", border: "2px solid #e2e8f0", borderRadius: 12, padding: 16 }}>
                  <p style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                    Breach Timeline
                  </p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {[...emailMetrics.year].sort((a, b) => Number(b[0]) - Number(a[0])).map(([year, count]) => (
                      <span key={year} style={{ fontSize: 11, fontFamily: "monospace", backgroundColor: "#fff", border: "1px solid #e2e8f0", color: "#475569", borderRadius: 6, padding: "3px 8px" }}>
                        {year}: <strong style={{ color: "#1e293b" }}>{count}</strong>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              <div style={{ backgroundColor: "#fff", border: "2px solid #e2e8f0", borderRadius: 10, padding: "12px 14px" }}>
                <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em" }}>Recommendations</p>
                <ul style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 4 }}>
                  {[
                    "Change passwords for all services listed above immediately.",
                    "Enable two-factor authentication (2FA) on every affected account.",
                    "Use the Password Generator to create unique passwords for each service.",
                    "Monitor your accounts for suspicious activity.",
                  ].map((tip, i) => (
                    <li key={i} style={{ fontSize: 12, color: "#475569", lineHeight: 1.5 }}>{tip}</li>
                  ))}
                </ul>
              </div>

              {/* Full details link */}
              <a
                href={`https://xposedornot.com/xposed/#${encodeURIComponent(email)}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 6, padding: "10px 0", borderRadius: 10, border: "2px solid #e2e8f0", backgroundColor: "#f8fafc", color: "#4f46e5", fontSize: 13, fontWeight: 600, textDecoration: "none" }}
              >
                <ExternalLink style={{ width: 14, height: 14 }} />
                View full breach details on XposedOrNot.com
              </a>
            </div>
          )}
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}