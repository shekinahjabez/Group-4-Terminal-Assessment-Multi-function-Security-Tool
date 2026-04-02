# 🔐 SecureKit — Multi-Function Security Tool

> **Group 4 · MO-IT142 Security Script Programming · Terminal Assessment AY 2025–2026**

A web-based security toolkit that combines practical password management, input validation, breach detection, and real network analysis tools — all in one place.

🔗 **Live App:** [securekit-whk3.onrender.com](https://securekit-whk3.onrender.com/)<br>
📄 **Documentation:** [View Full Documentation](https://docs.google.com/document/d/1xL3Gh5PcDcR--uXU91mk_smd5BoO1T_1MXnuNpH4ybY/edit?usp=sharing)<br>
🎬 **Demo Video:** [Watch on Google Drive](https://drive.google.com/file/d/1yWVxy-tE0VO6NI3PQXbQ8A4XzMnlqW0B/view?usp=sharing)<br>
💾 **Source Code:** [View on Google Drive](https://drive.google.com/drive/folders/1PDa-aMce2oslWlqfBKL2ofwpMdtkwGo8?usp=sharing)

---

## 🚀 Features

### Milestone 1 — Web Security Tools

#### 🔍 Password Strength Assessor
- Evaluate any password instantly with a real-time strength rating
- Checks against common password lists and dictionary words before scoring
- Scores 0–5 based on: 12+ characters, uppercase, lowercase, digits, and special characters
- Ratings: **Weak** (0–2) · **Moderate** (3–4) · **Strong** (5)

#### ⚡ Password Generator
- Generates cryptographically secure passwords between **4 and 128 characters**
- Every result is guaranteed to include uppercase, lowercase, digits, and special characters
- Returns both **SHA-256** and **bcrypt** (12-round) hashes for developer use
- Plaintext passwords are never stored — only hashes are logged

#### 🛡️ Form Input Validator
- Sanitizes and validates web form inputs against **XSS** and **SQL injection**
- Two-phase pipeline: sanitization first, then format validation
- Supports four field types:

  | Field | Rules |
  |---|---|
  | Full Name | Min 2 chars · Letters, spaces, hyphens, apostrophes only |
  | Email | Must contain `@` · Must end with a valid domain suffix |
  | Username | 4–16 chars · Cannot start with a digit · Letters, digits, underscores |
  | Message | Non-empty · Max 250 chars · No script tags or SQL keywords |

- SQL injection patterns are blocked immediately before any format check runs

---

> ### 🆕 New for Terminal Assessment — Leaked Password & Breach Checker
>
> This feature was added specifically for the Terminal Assessment submission. It extends the original Milestone 1 toolset with privacy-preserving breach detection across two independent tabs.
>
> #### Password Check tab
> Powered by the [Have I Been Pwned](https://haveibeenpwned.com/) Passwords API using the **k-anonymity model** — only the first 5 characters of the password's SHA-1 hash are ever sent over the network. All matching is done locally in the browser, so the plaintext password is never transmitted. Returns the exact number of times the password has appeared in known breach datasets.
>
> #### Email / Username tab
> Powered by the [XposedOrNot](https://xposedornot.com/) free, open-source API — no API key required. Enter any email address or username to get a list of every named breach it has appeared in, along with breach details.

---

---

### Milestone 2 — Network Security Tools

> Both tools require the **local agent** running on your machine with elevated privileges (`sudo` on Linux/macOS, or Run as Administrator on Windows).

#### 🌐 Port Scanner
- Performs a **TCP connect scan** with up to 100 parallel threads
- Three scan modes: **Common Ports**, **Port Range**, or **Custom** port list
- Adjustable per-port timeout (0.2–5.0 s)
- Open ports are classified by risk level:

  | Risk | Ports |
  |---|---|
  | 🔴 High | Telnet (23), FTP (21), RDP (3389), SMB (445) |
  | 🟡 Medium | SSH (22), DNS (53), SMTP (25) |
  | 🟢 Low | HTTP (80), HTTPS (443) |

- Port statuses: `OPEN` · `CLOSED` · `FILTERED`

#### 📡 Traffic Analyzer
- Streams live packet data to the browser via **Server-Sent Events**
- Set a capture duration (5–60 seconds) and optionally filter by protocol, port, source IP, or destination IP
- Each packet shows: source/destination, protocol, TCP flags, service name, size, suspicious flag, and timestamp
- Supports **PCAP export** at the end of each session
- Requires the local agent running with root/Administrator privileges (uses Python's **Scapy** library)

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React + TypeScript, Tailwind CSS |
| Backend | Python 3, FastAPI |
| Cryptography | bcrypt, SHA-256, SHA-1 (k-anonymity) |
| Network | Python `socket`, Scapy |
| Breach APIs | Have I Been Pwned, XposedOrNot |
| Hosting | Render |

---

## ⚙️ Local Agent Setup

The Port Scanner and Traffic Analyzer require a local agent running on your machine:

1. Open the **Scanner** or **Traffic** tool in the sidebar
2. Click **Enable Local Scanning** in the setup panel
3. Download the necessary files using the button in the panel (or clone the full repository)
4. Run the agent:
   - **Linux/macOS:** `bash StartAgent.sh` *(script prompts for `sudo` automatically)*
   - **Windows:** Right-click `StartAgent.bat` → **Run as Administrator**
5. Click the refresh icon in the setup panel to confirm the agent is detected

> ⚠️ **Important:** Download the full repository ZIP — the `src/` directory must be present alongside `local_agent.py`. Downloading only the script files is not sufficient.

### Browser Compatibility
- ✅ **Chrome / Edge** — fully supported
- ❌ **Firefox** — blocks connections from HTTPS pages to `http://127.0.0.1` by design; local agent will not work
- ⚠️ **Brave** — disable Brave Shields for `securekit-whk3.onrender.com` before enabling the local agent

---

## ⚠️ Scope & Limitations

SecureKit is an **educational tool** built for academic and controlled-environment use only. It is not an enterprise security platform.

| Capability | Status |
|---|---|
| TCP connect scanning | ✅ Supported |
| SYN / stealth scanning | ❌ Not supported |
| Breach checking via k-anonymity | ✅ Supported |
| Live packet capture (with sudo / Administrator) | ✅ Supported |
| Live packet capture (without elevated privileges) | ❌ Not available |
| Vulnerability exploitation | ❌ Not supported |
| Automated attack techniques | ❌ Not supported |
| Use on unauthorized networks | 🚫 Not permitted |

> **🚫 Authorized use only.** Always obtain explicit written permission before scanning any host or network you do not own. Unauthorized scanning or monitoring may violate local and international laws.

---

## 🐛 Common Issues

**First request is very slow**
The app is hosted on Render's free tier, which spins down after inactivity. The first request after a cold start can take **30–60 seconds**. Wait before retrying.

**"Local Agent Not Detected"**
- Confirm the terminal running the agent is still open
- Verify with: `curl http://127.0.0.1:8765/health`
- Check for port conflicts: `ss -tlnp | grep 8765` (Linux) or `netstat -ano | findstr :8765` (Windows)

**Stream/Snapshot buttons grayed out**
The agent is connected but Scapy is unavailable or running without elevated privileges. Restart using `StartAgent.sh` or **Run as Administrator** — do not run `sudo python3 local_agent.py` directly, as the system Python lacks the venv packages.

**Breach Checker returns an error**
Both the Have I Been Pwned and XposedOrNot APIs are external services. Check your internet connection and try again after a minute. The local agent is not required for the breach checker.
