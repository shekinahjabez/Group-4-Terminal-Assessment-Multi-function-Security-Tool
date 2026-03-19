import { useState } from "react";
import { CheckCircle2, XCircle, Shield} from "lucide-react";
const API = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");


interface FormData {
  fullName: string;
  email: string;
  username: string;
  message: string;
}

interface FieldValidation {
  isValid: boolean;
  sanitized: string;
  errors: string[];
  warnings: string[];
}

interface ValidationResult {
  fullName: FieldValidation;
  email: FieldValidation;
  username: FieldValidation;
  message: FieldValidation;
}

type ApiValidateResponse = {
  field_type: string;
  original: string;
  sanitized: string;
  was_sanitized: boolean;
  notes: string[];
  is_valid: boolean;
  errors: string[];
};

export function InputValidator() {
  const [formData, setFormData] = useState<FormData>({
    fullName: "",
    email: "",
    username: "",
    message: "",
  });

  const [result, setResult] = useState<ValidationResult | null>(null);
  const [loading, setLoading] = useState(false);

  const allFieldsFilled =
    formData.fullName && formData.email && formData.username && formData.message;

  const handleInputChange = (field: keyof FormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    setResult(null);
  };

  async function validateField(
  field_type: "name" | "email" | "username" | "message",
  value: string
): Promise<FieldValidation> {
  try {
    if (!API) {
      return {
        isValid: false,
        sanitized: "",
        errors: ["VITE_API_BASE_URL is not set"],
        warnings: [],
      };
    }

    const r = await fetch(`${API}/api/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ field_type, value }),
    });

    const ct = r.headers.get("content-type") || "";
    if (!ct.includes("application/json")) {
      const text = await r.text();
      return {
        isValid: false,
        sanitized: "",
        errors: [`Server returned ${r.status} (non-JSON)`],
        warnings: [text.slice(0, 120)],
      };
    }

    const data: ApiValidateResponse | any = await r.json();

    if (!r.ok) {
      const detail = data?.detail ? String(data.detail) : `Server returned ${r.status}`;
      return {
        isValid: false,
        sanitized: "",
        errors: [detail],
        warnings: [],
      };
    }

    return {
      isValid: Boolean(data.is_valid),
      sanitized: String(data.sanitized ?? ""),
      errors: Array.isArray(data.errors) ? data.errors.map(String) : [],
      warnings: Array.isArray(data.notes) ? data.notes.map(String) : [],
    };
  } catch (err: any) {
    return {
      isValid: false,
      sanitized: "",
      errors: [err?.message ? String(err.message) : "Network error while validating field."],
      warnings: [],
    };
  }
}

  const handleValidate = async () => {
    setLoading(true);
    setResult(null);

    try {
      const [fullName, email, username, message] = await Promise.all([
        validateField("name", formData.fullName),
        validateField("email", formData.email),
        validateField("username", formData.username),
        validateField("message", formData.message),
      ]);


      setResult({
        fullName,
        email,
        username,
        message,
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      {/* Header */}
      <div className="mb-2">
        <h2 className="text-sm font-bold text-slate-800 mb-0.5">Form Input Validator</h2>
        <p className="text-slate-600 text-[10px]">Validate and sanitize web form submissions (Python backend)</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {/* Left Column - Input Fields */}
        <div className="space-y-2">
          <div className="space-y-2">
            <div>
              <label className="block text-[10px] font-semibold text-slate-700 mb-1">Full Name</label>
              <input
                type="text"
                value={formData.fullName}
                onChange={(e) => handleInputChange("fullName", e.target.value)}
                placeholder="John Doe"
                className="w-full px-3 py-1.5 bg-slate-50 border-2 border-slate-200 rounded-lg text-slate-800 text-xs placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:bg-white transition-all"
              />
            </div>

            <div>
              <label className="block text-[10px] font-semibold text-slate-700 mb-1">Email Address</label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => handleInputChange("email", e.target.value)}
                placeholder="john@example.com"
                className="w-full px-3 py-1.5 bg-slate-50 border-2 border-slate-200 rounded-lg text-slate-800 text-xs placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:bg-white transition-all"
              />
            </div>

            <div>
              <label className="block text-[10px] font-semibold text-slate-700 mb-1">Username</label>
              <input
                type="text"
                value={formData.username}
                onChange={(e) => handleInputChange("username", e.target.value)}
                placeholder="johndoe123"
                className="w-full px-3 py-1.5 bg-slate-50 border-2 border-slate-200 rounded-lg text-slate-800 text-xs placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:bg-white transition-all"
              />
            </div>

            <div>
              <label className="block text-[10px] font-semibold text-slate-700 mb-1">Message</label>
              <textarea
                value={formData.message}
                onChange={(e) => handleInputChange("message", e.target.value)}
                placeholder="Your message here..."
                rows={2}
                className="w-full px-3 py-1.5 bg-slate-50 border-2 border-slate-200 rounded-lg text-slate-800 text-xs placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:bg-white transition-all resize-none"
              />
            </div>
          </div>

          <button
            onClick={handleValidate}
            disabled={!allFieldsFilled || loading}
            className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-300 disabled:cursor-not-allowed text-white font-semibold py-2 px-3 rounded-lg transition-all duration-200 shadow-lg shadow-indigo-600/20 hover:shadow-indigo-600/30 disabled:shadow-none flex items-center justify-center gap-2 text-xs"
          >
            <Shield className="w-3.5 h-3.5" />
            {loading ? "Validating..." : "Validate & Sanitize"}
          </button>
        </div>

        {/* Right Column - Results */}
        {result ? (
          <div className="space-y-2">
            <div className="bg-slate-50 rounded-lg p-2 border-2 border-slate-200">
              <h3 className="text-slate-800 font-bold text-[10px] uppercase tracking-wide mb-1.5">Validation Status</h3>
              <div className="space-y-1.5">
                {[
                  { field: "Full Name", validation: result.fullName },
                  { field: "Email", validation: result.email },
                  { field: "Username", validation: result.username },
                  { field: "Message", validation: result.message },
                ].map(({ field, validation }) => (
                  <div
                    key={field}
                    className={`flex items-center justify-between px-2 py-1.5 rounded-md border-2 transition-all ${
                      validation.isValid ? "bg-emerald-50 border-emerald-200" : "bg-red-50 border-red-200"
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      {validation.isValid ? (
                        <CheckCircle2 className="w-3 h-3 text-emerald-600 flex-shrink-0" />
                      ) : (
                        <XCircle className="w-3 h-3 text-red-600 flex-shrink-0" />
                      )}
                      <span className={`text-[10px] font-medium ${validation.isValid ? "text-emerald-700" : "text-red-700"}`}>
                        {field}
                      </span>
                    </div>
                    <div className="text-right">
                      {validation.errors.length > 0 && <p className="text-red-600 text-[10px]">{validation.errors[0]}</p>}
                      {validation.warnings.length > 0 && <p className="text-orange-600 text-[10px]">{validation.warnings[0]}</p>}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-slate-50 rounded-lg p-2 border-2 border-slate-200">
              <h3 className="text-slate-800 font-bold text-[10px] uppercase tracking-wide mb-1.5">Sanitized Data</h3>
              <div className="bg-white rounded-md p-2 border-2 border-slate-200 space-y-1.5">
                <div>
                  <span className="text-slate-500 text-[10px] font-semibold uppercase">Full Name:</span>
                  <p className="text-slate-800 text-[10px] mt-0.5">{result.fullName.sanitized || "(empty)"}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] font-semibold uppercase">Email:</span>
                  <p className="text-slate-800 text-[10px] mt-0.5">{result.email.sanitized || "(empty)"}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] font-semibold uppercase">Username:</span>
                  <p className="text-slate-800 text-[10px] mt-0.5">{result.username.sanitized || "(empty)"}</p>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] font-semibold uppercase">Message:</span>
                  <p className="text-slate-800 text-[10px] mt-0.5 break-words">{result.message.sanitized || "(empty)"}</p>
                </div>
              </div>
            </div>


            <div className="bg-gradient-to-r from-emerald-50 to-green-50 border-2 border-emerald-300 rounded-lg p-2 text-center">
              <p className="text-emerald-700 font-bold text-xs">✓ Validation Complete</p>
              <p className="text-emerald-600 text-[10px] mt-0.5">All form data has been validated and sanitized</p>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="bg-gradient-to-br from-indigo-50 to-blue-50 rounded-lg p-2 border-2 border-indigo-200">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Shield className="w-3.5 h-3.5 text-indigo-600" />
                <h3 className="text-indigo-800 font-bold text-[10px]">Security Validation</h3>
              </div>
              <p className="text-[10px] text-slate-700">
                Fill in all fields to validate. Results will appear here after the backend sanitizes and checks each field.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
