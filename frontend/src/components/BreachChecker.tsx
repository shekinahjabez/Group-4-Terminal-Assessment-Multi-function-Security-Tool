import { useState } from "react";
import { ShieldAlert, ShieldCheck, Eye, EyeOff, AlertCircle, Loader2, Lock, Mail } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

type CheckTab = "password" | "email";

interface PwnedPasswordResult {
  found: boolean;
  count: number;   // number of times seen in breaches
  hash:  string;   // full SHA-1 hash (computed locally)
}

interface BreachEntry {
  Name:        string;
  BreachDate:  string;
  PwnCount:    number;
  DataClasses: string[];
  Description: string;
  IsVerified:  boolean;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// computes sha-1 hash of a string using the browser's web crypto API
async function sha1(str: string): Promise<string> {
  const buf  = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function formatCount(n: number): string {
  return n.toLocaleString();
}

// severity label based on breach exposure count
function severityFromCount(count: number): { label: string; color: string; bg: string; border: string } {
  if (count > 100_000) return { label: "Critical", color: "#b91c1c", bg: "#fef2f2", border: "#fecaca" };
  if (count > 10_000)  return { label: "High",     color: "#c2410c", bg: "#fff7ed", border: "#fed7aa" };
  if (count > 1_000)   return { label: "Medium",   color: "#a16207", bg: "#fefce8", border: "#fef08a" };
  return                      { label: "Low",      color: "#166534", bg: "#f0fdf4", border: "#bbf7d0" };
}

// ── Password check (k-anonymity via HIBP range API) ────────────────────────────

async function checkPasswordBreach(password: string): Promise<PwnedPasswordResult> {
  const hash   = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res  = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!res.ok) throw new Error(`HIBP API error: ${res.status}`);
  const text = await res.text();

  let count = 0;
  for (const line of text.split("\r\n")) {
    const [s, c] = line.split(":");
    if (s === suffix) { count = parseInt(c, 10); break; }
  }

  return { found: count > 0, count, hash };
}

// ── Component ──────────────────────────────────────────────────────────────────

export function BreachChecker() {
  const [tab,          setTab]          = useState<CheckTab>("password");

  // password tab state
  const [password,     setPassword]     = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [pwLoading,    setPwLoading]    = useState(false);
  const [pwResult,     setPwResult]     = useState<PwnedPasswordResult | null>(null);
  const [pwError,      setPwError]      = useState<string | null>(null);
  const [pwEmpty,      setPwEmpty]      = useState(false);

  // email tab state
  const [email,        setEmail]        = useState("");
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailResult,  setEmailResult]  = useState<BreachEntry[] | null>(null);
  const [emailSafe,    setEmailSafe]    = useState(false);
  const [emailError,   setEmailError]   = useState<string | null>(null);
  const [emailEmpty,   setEmailEmpty]   = useState(false);

  // ── Password check handler ──────────────────────────────────────────────────

  const handlePasswordCheck = async () => {
    if (!password.trim()) { setPwEmpty(true); setPwResult(null); setPwError(null); return; }
    setPwEmpty(false); setPwError(null); setPwResult(null); setPwLoading(true);
    try {
      const result = await checkPasswordBreach(password);
      setPwResult(result);
    } catch (err) {
      setPwError(err instanceof Error ? err.message : "Network error. Please try again.");
    } finally {
      setPwLoading(false);
    }
  };

  // ── Email check handler ─────────────────────────────────────────────────────
  // note: HIBP v3 email endpoint requires an API key — this shows a helpful
  // message guiding the user to check directly on haveibeenpwned.com

  const handleEmailCheck = async () => {
    if (!email.trim()) { setEmailEmpty(true); setEmailResult(null); setEmailError(null); setEmailSafe(false); return; }
    setEmailEmpty(false); setEmailError(null); setEmailResult(null); setEmailSafe(false); setEmailLoading(true);
    try {
      const res = await fetch(
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email.trim())}?truncateResponse=false`,
        { headers: { "hibp-api-key": "", "user-agent": "SecureKit-BreachChecker" } }
      );
      if (res.status === 404) { setEmailSafe(true); return; }
      if (res.status === 401) {
        setEmailError(
          "The HIBP email API requires a personal API key (v3). You can check your email directly at haveibeenpwned.com, or add your API key to this component's source."
        );
        return;
      }
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data: BreachEntry[] = await res.json();
      data.sort((a, b) => new Date(b.BreachDate).getTime() - new Date(a.BreachDate).getTime());
      setEmailResult(data);
    } catch (err) {
      setEmailError(err instanceof Error ? err.message : "Network error. Please try again.");
    } finally {
      setEmailLoading(false);
    }
  };

  // ── Shared style tokens (mirrors PortScanner / PasswordStrength) ─────────────

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

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* Header */}
      <div>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: "#1e293b", margin: 0 }}>
          Leaked Password &amp; Breach Checker
        </h2>
        <p style={{ fontSize: 12, color: "#64748b", margin: "4px 0 0" }}>
          Check if your password or email appeared in known data breaches (HaveIBeenPwned)
        </p>
      </div>

      {/* Privacy note */}
      <div style={{ backgroundColor: "#f0fdf4", border: "2px solid #bbf7d0", borderRadius: 10, padding: "10px 14px", display: "flex", alignItems: "center", gap: 10 }}>
        <Lock style={{ width: 15, height: 15, color: "#16a34a", flexShrink: 0 }} />
        <p style={{ margin: 0, fontSize: 12, color: "#166534", lineHeight: 1.5 }}>
          <strong>k-anonymity:</strong> Your password is never sent over the network.
          Only the first 5 characters of its SHA-1 hash are transmitted; matching is done locally in your browser.
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

      {/* ── Password Tab ── */}
      {tab === "password" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

          {/* Input */}
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
              <button
                type="button"
                onClick={() => setShowPassword(s => !s)}
                style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: "#94a3b8", padding: 2 }}
              >
                {showPassword ? <EyeOff style={{ width: 18, height: 18 }} /> : <Eye style={{ width: 18, height: 18 }} />}
              </button>
            </div>
          </div>

          {/* Button */}
          <button
            onClick={handlePasswordCheck}
            disabled={pwLoading}
            style={primaryBtn(pwLoading)}
            onMouseEnter={e => { if (!pwLoading) e.currentTarget.style.backgroundColor = "#4338ca"; }}
            onMouseLeave={e => { if (!pwLoading) e.currentTarget.style.backgroundColor = "#4f46e5"; }}
          >
            {pwLoading
              ? <><Loader2 style={{ width: 16, height: 16, animation: "spin 0.7s linear infinite" }} />Checking...</>
              : <><ShieldAlert style={{ width: 16, height: 16 }} />Check Password</>}
          </button>

          {/* Empty error */}
          {pwEmpty && (
            <div style={{ backgroundColor: "#fef2f2", borderLeft: "4px solid #ef4444", borderRadius: 8, padding: "10px 14px", display: "flex", alignItems: "center", gap: 10 }}>
              <AlertCircle style={{ width: 16, height: 16, color: "#dc2626", flexShrink: 0 }} />
              <span style={{ fontSize: 13, color: "#b91c1c", fontWeight: 500 }}>Please enter a password to check.</span>
            </div>
          )}

          {/* API error */}
          {pwError && (
            <div style={{ backgroundColor: "#fef2f2", border: "2px solid #fecaca", borderRadius: 10, padding: "10px 14px", color: "#dc2626", fontSize: 12, display: "flex", gap: 8 }}>
              <span style={{ fontWeight: 700 }}>Error:</span><span>{pwError}</span>
            </div>
          )}

          {/* Result */}
          {pwResult && (() => {
            const sev = pwResult.found ? severityFromCount(pwResult.count) : null;
            return pwResult.found ? (
              <div style={{ backgroundColor: sev!.bg, border: `2px solid ${sev!.border}`, borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>

                {/* Status row */}
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 44, height: 44, backgroundColor: sev!.bg, border: `2px solid ${sev!.border}`, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <ShieldAlert style={{ width: 22, height: 22, color: sev!.color }} />
                  </div>
                  <div>
                    <p style={{ margin: 0, fontSize: 16, fontWeight: 700, color: sev!.color }}>Password Compromised</p>
                    <p style={{ margin: "2px 0 0", fontSize: 12, color: "#64748b" }}>
                      Found in <strong style={{ color: sev!.color }}>{formatCount(pwResult.count)}</strong> breach record{pwResult.count !== 1 ? "s" : ""}
                    </p>
                  </div>
                  <span style={{ marginLeft: "auto", backgroundColor: sev!.bg, border: `1px solid ${sev!.border}`, color: sev!.color, borderRadius: 999, padding: "3px 12px", fontSize: 11, fontWeight: 700 }}>
                    {sev!.label} Risk
                  </span>
                </div>

                {/* Stats */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  {[
                    { label: "Exposures",  value: formatCount(pwResult.count) },
                    { label: "Risk Level", value: sev!.label                  },
                  ].map(s => (
                    <div key={s.label} style={{ backgroundColor: "#fff", border: "2px solid #e2e8f0", borderRadius: 10, padding: "10px 12px", textAlign: "center" }}>
                      <p style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>{s.label}</p>
                      <p style={{ fontSize: 14, fontWeight: 700, color: sev!.color, margin: "4px 0 0" }}>{s.value}</p>
                    </div>
                  ))}
                </div>

                {/* Advice */}
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

                {/* Hash (for technical users) */}
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
                    This password was not found in any known breach database.
                    Make sure it's also long and unique for best protection.
                  </p>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* ── Email Tab ── */}
      {tab === "email" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

          {/* Input */}
          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "#475569", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Email or Username
            </label>
            <input
              type="email"
              value={email}
              onChange={e => { setEmail(e.target.value); setEmailEmpty(false); setEmailResult(null); setEmailError(null); setEmailSafe(false); }}
              onKeyDown={e => e.key === "Enter" && handleEmailCheck()}
              placeholder="email@example.com"
              style={inputStyle}
              onFocus={e => (e.currentTarget.style.borderColor = "#4f46e5")}
              onBlur={e  => (e.currentTarget.style.borderColor = "#e2e8f0")}
            />
          </div>

          {/* Button */}
          <button
            onClick={handleEmailCheck}
            disabled={emailLoading}
            style={primaryBtn(emailLoading)}
            onMouseEnter={e => { if (!emailLoading) e.currentTarget.style.backgroundColor = "#4338ca"; }}
            onMouseLeave={e => { if (!emailLoading) e.currentTarget.style.backgroundColor = "#4f46e5"; }}
          >
            {emailLoading
              ? <><Loader2 style={{ width: 16, height: 16, animation: "spin 0.7s linear infinite" }} />Checking...</>
              : <><ShieldAlert style={{ width: 16, height: 16 }} />Check Email</>}
          </button>

          {/* Empty error */}
          {emailEmpty && (
            <div style={{ backgroundColor: "#fef2f2", borderLeft: "4px solid #ef4444", borderRadius: 8, padding: "10px 14px", display: "flex", alignItems: "center", gap: 10 }}>
              <AlertCircle style={{ width: 16, height: 16, color: "#dc2626", flexShrink: 0 }} />
              <span style={{ fontSize: 13, color: "#b91c1c", fontWeight: 500 }}>Please enter an email or username.</span>
            </div>
          )}

          {/* API / network error */}
          {emailError && (
            <div style={{ backgroundColor: "#fffbeb", border: "2px solid #fde68a", borderRadius: 10, padding: "12px 14px", display: "flex", flexDirection: "column", gap: 6 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <AlertCircle style={{ width: 15, height: 15, color: "#b45309", flexShrink: 0 }} />
                <span style={{ fontSize: 12, fontWeight: 700, color: "#92400e" }}>API Key Required</span>
              </div>
              <p style={{ margin: 0, fontSize: 12, color: "#78350f", lineHeight: 1.6 }}>{emailError}</p>
              <a href="https://haveibeenpwned.com" target="_blank" rel="noopener noreferrer"
                style={{ display: "inline-flex", alignItems: "center", gap: 6, marginTop: 4, fontSize: 12, fontWeight: 600, color: "#4f46e5", textDecoration: "none" }}
              >
                Check on haveibeenpwned.com →
              </a>
            </div>
          )}

          {/* Safe result */}
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

          {/* Breach list */}
          {emailResult && emailResult.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

              {/* Summary bar */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {[
                  { label: "Breaches Found",  value: String(emailResult.length)                                           },
                  { label: "Total Accounts",  value: formatCount(emailResult.reduce((a, b) => a + b.PwnCount, 0))         },
                ].map(s => (
                  <div key={s.label} style={{ backgroundColor: "#fef2f2", border: "2px solid #fecaca", borderRadius: 10, padding: "10px 12px", textAlign: "center" }}>
                    <p style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.05em", margin: 0 }}>{s.label}</p>
                    <p style={{ fontSize: 14, fontWeight: 700, color: "#b91c1c", margin: "4px 0 0" }}>{s.value}</p>
                  </div>
                ))}
              </div>

              {/* Individual breach cards */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 360, overflowY: "auto" }}>
                {emailResult.map(breach => (
                  <div key={breach.Name} style={{ backgroundColor: "#fff", border: "2px solid #e2e8f0", borderRadius: 10, padding: "12px 14px" }}>
                    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 10, marginBottom: 6 }}>
                      <p style={{ margin: 0, fontSize: 13, fontWeight: 700, color: "#1e293b" }}>{breach.Name}</p>
                      <span style={{ flexShrink: 0, backgroundColor: "#fef2f2", border: "1px solid #fecaca", color: "#b91c1c", borderRadius: 999, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>
                        {formatCount(breach.PwnCount)} accounts
                      </span>
                    </div>
                    <div style={{ display: "flex", gap: 12, marginBottom: 8 }}>
                      <span style={{ fontSize: 11, color: "#64748b", fontFamily: "monospace" }}>📅 {breach.BreachDate || "Unknown date"}</span>
                      {breach.IsVerified && (
                        <span style={{ fontSize: 10, backgroundColor: "#f0fdf4", border: "1px solid #bbf7d0", color: "#166534", borderRadius: 999, padding: "1px 8px", fontWeight: 600 }}>Verified</span>
                      )}
                    </div>
                    {breach.DataClasses?.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                        {breach.DataClasses.slice(0, 6).map(dc => (
                          <span key={dc} style={{ fontSize: 10, fontFamily: "monospace", backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", color: "#64748b", borderRadius: 999, padding: "2px 8px" }}>
                            {dc}
                          </span>
                        ))}
                        {breach.DataClasses.length > 6 && (
                          <span style={{ fontSize: 10, color: "#94a3b8" }}>+{breach.DataClasses.length - 6} more</span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Info note about email API */}
          {!emailResult && !emailSafe && !emailError && !emailLoading && (
            <div style={{ backgroundColor: "#eff6ff", border: "2px solid #bfdbfe", borderRadius: 12, padding: 20, textAlign: "center" }}>
              <Mail style={{ width: 28, height: 28, color: "#3b82f6", marginBottom: 8 }} />
              <p style={{ fontSize: 13, fontWeight: 600, color: "#1e40af", margin: "0 0 4px" }}>Email breach lookup</p>
              <p style={{ fontSize: 12, color: "#3b82f6", margin: 0 }}>
                Requires a HaveIBeenPwned API key (v3). Enter your email and try — or visit haveibeenpwned.com directly.
              </p>
            </div>
          )}
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}