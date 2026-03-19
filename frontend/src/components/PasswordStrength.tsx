import { useState } from "react";
import { Eye, EyeOff, AlertCircle, CheckCircle2, XCircle } from "lucide-react";

interface StrengthResult {
  score: number; // 0..8 for your bars
  label: string; // Weak | Moderate | Strong
  color: string;
  feedback: string[];
  details: {
    length: boolean; // >=12 (matches backend scoring rule)
    uppercase: boolean;
    lowercase: boolean;
    numbers: boolean;
    symbols: boolean;
    commonPassword: boolean; // can't know exactly (COMMON_PASSWORDS list is server-side)
  };
}

type ApiAssessResponse = {
  result: [string, string]; // ("Weak"|"Moderate"|"Strong", message)
};

function labelToUI(label: string) {
  const l = (label || "").toLowerCase();
  if (l === "weak") return { score: 2, color: "text-red-600", label: "Weak" };
  if (l === "moderate") return { score: 4, color: "text-orange-500", label: "Moderate" };
  if (l === "strong") return { score: 7, color: "text-emerald-600", label: "Strong" };
  return { score: 0, color: "text-red-600", label: label || "Unknown" };
}

function computeDetailsFromRules(pwd: string) {
  // Mirrors your backend rules:
  return {
    length: pwd.length >= 12,
    uppercase: /[A-Z]/.test(pwd),
    lowercase: /[a-z]/.test(pwd),
    numbers: /[0-9]/.test(pwd),
    symbols: /[!@#$%^&*()_+=\-[\]{};:'",.<>?/\\|]/.test(pwd),
    // We can't check server-side COMMON_PASSWORDS/DICTIONARY_WORDS here reliably.
    // We'll mark it "unknown but assumed ok" unless backend indicates it's common/dictionary.
    commonPassword: true,
  };
}

function messageToFeedback(label: string, message: string) {
  const msg = (message || "").trim();
  if (!msg) return [];

  // If backend says it's common/dictionary, show that as feedback
  const lower = msg.toLowerCase();
  if (lower.includes("commonly used")) return [msg];
  if (lower.includes("dictionary word")) return [msg];

  // Backend uses bullet lines like "• Add numbers."
  const lines = msg
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => s.replace(/^•\s*/, "")); // remove leading bullet

  // Strong case message is single sentence
  if (lines.length === 0) return [msg];

  // If strong, we can still show it
  if (label.toLowerCase() === "strong" && lines.length === 1) return lines;

  return lines;
}

export function PasswordStrength() {
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [result, setResult] = useState<StrengthResult | null>(null);
  const [showEmptyError, setShowEmptyError] = useState(false);
  const [loading, setLoading] = useState(false);

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    setShowEmptyError(false);
    setResult(null);
  };

  const handleCheckPassword = async () => {
  if (password.trim().length === 0) {
    setShowEmptyError(true);
    setResult(null);
    return;
  }

  setShowEmptyError(false);
  setLoading(true);

  try {
    const API = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");
    if (!API) throw new Error("VITE_API_BASE_URL is not set");

    const r = await fetch(`${API}/api/assess`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    // ✅ Safety: detect HTML/non-JSON responses
    const ct = r.headers.get("content-type") || "";
    if (!ct.includes("application/json")) {
      const text = await r.text();
      throw new Error(`Expected JSON, got ${ct}. Body: ${text.slice(0, 120)}`);
    }

    const data: ApiAssessResponse | any = await r.json();

    if (!r.ok) {
      const msg = data?.detail ? String(data.detail) : "Failed to assess password.";
      const details = computeDetailsFromRules(password);
      setResult({
        score: 0,
        label: "Weak",
        color: "text-red-600",
        feedback: [msg],
        details,
      });
      return;
    }

    const tuple = data?.result;
    const backendLabel = Array.isArray(tuple) ? String(tuple[0]) : "Weak";
    const backendMessage = Array.isArray(tuple) ? String(tuple[1] ?? "") : "";

    const ui = labelToUI(backendLabel);
    const details = computeDetailsFromRules(password);

    // If backend explicitly says common/dictionary, reflect that in the checklist
    const msgLower = backendMessage.toLowerCase();
    if (msgLower.includes("commonly used") || msgLower.includes("dictionary word")) {
      details.commonPassword = false;
    }

    const feedback = messageToFeedback(backendLabel, backendMessage);

    setResult({
      score: ui.score,
      label: ui.label,
      color: ui.color,
      feedback: feedback.length ? feedback : ["Password meets security requirements."],
      details,
    });
  } catch (err) {
    console.error(err);
    const details = computeDetailsFromRules(password);
    setResult({
      score: 0,
      label: "Weak",
      color: "text-red-600",
      feedback: ["Network error while assessing password."],
      details,
    });
  } finally {
    setLoading(false);
  }
};

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-800 mb-1">Password Strength Analyzer</h2>
        <p className="text-slate-600 text-sm">Evaluate the security level of your password (Python backend)</p>
      </div>

      {/* Password Input */}
      <div className="relative">
        <label className="block text-sm font-semibold text-slate-700 mb-2">Enter Password</label>
        <div className="relative">
          <input
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={handlePasswordChange}
            placeholder="Type your password here..."
            className="w-full px-4 py-3 bg-slate-50 border-2 border-slate-200 rounded-xl text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white transition-all pr-12"
            onKeyDown={(e) => {
              if (e.key === "Enter") handleCheckPassword();
            }}
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-blue-600 transition-colors"
            title={showPassword ? "Hide" : "Show"}
          >
            {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Check Password Button */}
      <button
        onClick={handleCheckPassword}
        disabled={loading}
        className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 disabled:cursor-not-allowed text-white font-semibold py-3 px-6 rounded-xl transition-all duration-200 shadow-lg shadow-blue-600/20 hover:shadow-blue-600/30"
      >
        {loading ? "Analyzing..." : "Analyze Password"}
      </button>

      {/* Empty Input Error */}
      {showEmptyError && (
        <div className="bg-red-50 border-l-4 border-red-500 rounded-lg p-4">
          <div className="flex items-center gap-3 text-red-700">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <p className="font-medium">Please enter a password to analyze</p>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left Column */}
          <div className="space-y-4">
            <div className="bg-slate-50 rounded-xl p-5 border-2 border-slate-200">
              <div className="flex items-center justify-between mb-3">
                <span className="text-slate-700 font-semibold text-sm uppercase tracking-wide">Strength Level</span>
                <span className={`font-bold text-lg ${result.color}`}>{result.label}</span>
              </div>

              <div className="grid grid-cols-8 gap-1.5 mb-2">
                {[...Array(8)].map((_, i) => (
                  <div
                    key={i}
                    className={`h-2.5 rounded-full transition-all duration-500 ${
                      i < result.score
                        ? result.label === "Weak"
                          ? "bg-red-500"
                          : result.label === "Moderate"
                          ? "bg-orange-500"
                          : "bg-emerald-500"
                        : "bg-slate-200"
                    }`}
                  />
                ))}
              </div>

              <p className="text-center text-slate-500 text-sm font-medium">Security Rating: {result.label}</p>
            </div>

            {result.feedback.length > 0 && (
              <div className="bg-blue-50 border-l-4 border-blue-500 rounded-lg p-4">
                <h3 className="font-bold text-blue-900 mb-2 flex items-center gap-2 text-sm uppercase tracking-wide">
                  <AlertCircle className="w-4 h-4" />
                  Recommendations
                </h3>
                <ul className="space-y-1.5">
                  {result.feedback.map((item, index) => (
                    <li key={index} className="text-blue-800 flex items-start gap-2 text-sm">
                      <span className="text-blue-500 font-bold mt-0.5">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Right Column */}
          <div>
            <h3 className="text-slate-800 font-bold text-sm uppercase tracking-wide mb-3">Security Checks</h3>
            <div className="grid grid-cols-1 gap-2.5">
              {Object.entries({
                length: "12+ characters",
                uppercase: "Uppercase (A-Z)",
                lowercase: "Lowercase (a-z)",
                numbers: "Numbers (0-9)",
                symbols: "Symbols (!@#)",
                commonPassword: "Not common / dictionary",
              }).map(([key, label]) => {
                const passed = result.details[key as keyof typeof result.details];
                return (
                  <div
                    key={key}
                    className={`flex items-center justify-between px-4 py-2.5 rounded-lg border-2 transition-all ${
                      passed ? "bg-emerald-50 border-emerald-200" : "bg-red-50 border-red-200"
                    }`}
                  >
                    <span className={`text-sm font-medium ${passed ? "text-emerald-700" : "text-red-700"}`}>{label}</span>
                    {passed ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
                    )}
                  </div>
                );
              })}
            </div>

            <p className="mt-2 text-[11px] text-slate-500">
              Note: “Not common / dictionary” is determined by the backend’s password lists.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
