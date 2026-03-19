import { useState } from "react";
import { Copy, RefreshCw, Check, Eye, EyeOff, Hash, Download } from "lucide-react";
import * as bcrypt from "bcryptjs";
import * as XLSX from "xlsx";

export function PasswordGenerator() {
  const [password, setPassword] = useState("");
  const [length, setLength] = useState(16);

  const [copied, setCopied] = useState(false);
  const [showPassword, setShowPassword] = useState(true);

  const [sha256Hash, setSha256Hash] = useState("");
  const [bcryptHash, setBcryptHash] = useState("");
  const [lastTimestamp, setLastTimestamp] = useState<string>("");

  // UI helpers
  const getLengthColor = () => {
    if (length < 10) return "text-red-600";
    if (length < 13) return "text-amber-600";
    return "text-emerald-600";
  };

  const getLengthGradient = () => {
    const min = 8;
    const max = 16;
    const percent = ((length - min) / (max - min)) * 100;

    let color = "rgb(220, 38, 38)"; // red-600
    if (length >= 10 && length < 13) color = "rgb(217, 119, 6)"; // amber-600
    if (length >= 13) color = "rgb(5, 150, 105)"; // emerald-600

    return {
      background: `linear-gradient(to right, ${color} 0%, ${color} ${percent}%, rgb(226, 232, 240) ${percent}%, rgb(226, 232, 240) 100%)`,
    } as React.CSSProperties;
  };

  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);

  const generatePassword = async () => {
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_-+={}[];:,.?";

    const charset = uppercase + lowercase + numbers + symbols;

    const getRandomChar = (charSet: string) => {
      const array = new Uint32Array(1);
      window.crypto.getRandomValues(array);
      return charSet[array[0] % charSet.length];
    };

    // Ensure at least one from each category
    let required = "";
    required += getRandomChar(uppercase);
    required += getRandomChar(lowercase);
    required += getRandomChar(numbers);
    required += getRandomChar(symbols);

    const remainingLength = Math.max(0, length - required.length);
    const array = new Uint32Array(remainingLength);
    window.crypto.getRandomValues(array);

    let generated = required;
    for (let i = 0; i < array.length; i++) {
      generated += charset[array[i] % charset.length];
    }

    // Shuffle
    const chars = generated.split("");
    for (let i = chars.length - 1; i > 0; i--) {
      const r = new Uint32Array(1);
      window.crypto.getRandomValues(r);
      const j = r[0] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    generated = chars.join("");

    setPassword(generated);
    setCopied(false);

    await hashPassword(generated);

    const now = new Date();
    const ts = now.toLocaleString("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
    setLastTimestamp(ts);
  };

  const hashPassword = async (pwd: string) => {
    // SHA-256
    const encoder = new TextEncoder();
    const data = encoder.encode(pwd);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    setSha256Hash(hashHex);

    // bcrypt
    const salt = bcrypt.genSaltSync(10);
    const bHash = bcrypt.hashSync(pwd, salt);
    setBcryptHash(bHash);
  };

  const copyToClipboard = (text: string) => {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-999999px";
    textarea.style.top = "-999999px";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();

    try {
      document.execCommand("copy");
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } finally {
      document.body.removeChild(textarea);
    }
  };


  const downloadExcel = () => {
    if (!sha256Hash || !bcryptHash) {
      alert("Generate a password first.");
      return;
    }

    const rows = [
      {
        Timestamp: lastTimestamp || "",
        "SHA-256": sha256Hash,
        Bcrypt: bcryptHash,
      },
    ];

    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Generated");
    XLSX.writeFile(wb, "securekit_password_hashes.xlsx");
  };

  return (
    <div className="space-y-3">
      {/* Header */}
      <div>
        <h2 className="text-lg font-bold text-slate-800 mb-0.5">Password Generator</h2>
        <p className="text-slate-600 text-xs">Create cryptographically secure passwords</p>
      </div>

      {/* Generate Button */}
      <button
        onClick={generatePassword}
        className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-semibold py-3 px-4 rounded-xl transition-all duration-200 shadow-lg shadow-emerald-600/20 hover:shadow-emerald-600/30 flex items-center justify-center gap-2"
      >
        <RefreshCw className="w-4 h-4" />
        Generate Password
      </button>

      {/* Generated Password Display */}
      {password && (
        <div className="space-y-3">
          {/* Password Display */}
          <div className="bg-emerald-50 rounded-xl p-4 border-2 border-emerald-200">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-700 font-semibold text-xs uppercase tracking-wide">Your Password</span>
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="text-slate-400 hover:text-emerald-600 transition-colors"
                title={showPassword ? "Hide" : "Show"}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                readOnly
                className="w-full px-4 py-3 bg-white border-2 border-emerald-300 rounded-xl text-emerald-700 font-mono text-sm focus:outline-none pr-12"
              />
              <button
                onClick={() => copyToClipboard(password)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-emerald-600 transition-colors"
                title="Copy password"
              >
                {copied ? <Check className="w-5 h-5 text-emerald-600" /> : <Copy className="w-5 h-5" />}
              </button>
            </div>

            <p className="text-[10px] text-slate-500 mt-2">
              Note: Excel download exports hashes only (no plaintext password).
            </p>
          </div>

          {/* Character Types */}
          <div className="bg-slate-50 rounded-xl p-4 border-2 border-slate-200">
            <h3 className="text-xs font-semibold text-slate-700 mb-3 uppercase tracking-wide">
              Character Types
            </h3>

            <div className="grid grid-cols-2 gap-2 text-sm">
              <div className={`flex items-center gap-2 ${hasUpper ? "text-emerald-600" : "text-slate-400"}`}>
                <span>{hasUpper ? "✔" : "✖"}</span>
                Uppercase (A–Z)
              </div>

              <div className={`flex items-center gap-2 ${hasLower ? "text-emerald-600" : "text-slate-400"}`}>
                <span>{hasLower ? "✔" : "✖"}</span>
                Lowercase (a–z)
              </div>

              <div className={`flex items-center gap-2 ${hasNumber ? "text-emerald-600" : "text-slate-400"}`}>
                <span>{hasNumber ? "✔" : "✖"}</span>
                Numbers (0–9)
              </div>

              <div className={`flex items-center gap-2 ${hasSymbol ? "text-emerald-600" : "text-slate-400"}`}>
                <span>{hasSymbol ? "✔" : "✖"}</span>
                Symbols (!@#)
              </div>
            </div>
          </div>

          {/* Hash Displays */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <div className="bg-slate-50 rounded-xl p-3 border-2 border-slate-200">
              <div className="flex items-center gap-2 mb-2">
                <Hash className="w-4 h-4 text-blue-600" />
                <h3 className="font-bold text-slate-800 text-xs">SHA-256 Hash</h3>
              </div>
              <input
                type="text"
                value={sha256Hash}
                readOnly
                className="w-full px-3 py-2 bg-white border-2 border-slate-200 rounded-lg text-blue-600 font-mono text-xs focus:outline-none"
              />
            </div>

            <div className="bg-slate-50 rounded-xl p-3 border-2 border-slate-200">
              <div className="flex items-center gap-2 mb-2">
                <Hash className="w-4 h-4 text-indigo-600" />
                <h3 className="font-bold text-slate-800 text-xs">Bcrypt Hash</h3>
              </div>
              <input
                type="text"
                value={bcryptHash}
                readOnly
                className="w-full px-3 py-2 bg-white border-2 border-slate-200 rounded-lg text-indigo-600 font-mono text-xs focus:outline-none"
              />
            </div>
          </div>

          {/* Download Button */}
          <button
            onClick={downloadExcel}
            className="w-full bg-slate-100 hover:bg-slate-200 border-2 border-slate-300 text-slate-700 font-semibold py-3 px-4 rounded-xl transition-all flex items-center justify-center gap-2"
          >
            <Download className="w-4 h-4" />
            <span className="text-sm">Download Excel </span>
          </button>
        </div>
      )}

      {/* Password Length */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs font-semibold text-slate-700">Password Length</label>
          <span className={`text-lg font-bold ${getLengthColor()}`}>{length}</span>
        </div>

        <input
          type="range"
          min="8"
          max="16"
          value={length}
          onChange={(e) => setLength(Number(e.target.value))}
          className="w-full h-2 rounded-full appearance-none cursor-pointer"
          style={getLengthGradient()}
        />

        <div className="flex justify-between text-xs text-slate-500 mt-1 font-medium">
          <span>8 chars</span>
          <span>16 chars</span>
        </div>
      </div>
    </div>
  );
}
