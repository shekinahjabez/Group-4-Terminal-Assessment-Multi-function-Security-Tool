// TourSteps.ts — Step-by-step guide content for each tool
import type { TourStep } from "./components/TourGuide";

export const TOUR_STEPS: Record<string, TourStep[]> = {

  // ── Password Strength ────────────────────────────────────────────────────
  strength: [
    {
      target: '[data-tour="strength-input"]',
      title: "Enter Your Password",
      content: "Type any password in this field to analyze how strong it is. Your password stays in your browser and is never sent anywhere.",
      tip: "Try a weak password like '123456' first, then gradually make it stronger to see the score change.",
      position: "bottom",
    },
    {
      target: '[data-tour="strength-meter"]',
      title: "Strength Meter",
      content: "This bar visually shows your password strength — red means weak, yellow means fair, and green means strong. It updates after you click Analyze.",
      tip: "A strong password fills the bar completely in green.",
      position: "bottom",
    },
    {
      target: '[data-tour="strength-score"]',
      title: "Strength Rating",
      content: "This label (Weak / Moderate / Strong) is determined by the Python backend, which checks your password against common password lists and dictionary words.",
      position: "right",
    },
    {
      target: '[data-tour="strength-feedback"]',
      title: "Recommendations",
      content: "Here you'll see specific suggestions from the backend — such as adding uppercase letters, numbers, or symbols — so you know exactly what to improve.",
      tip: "Fix each suggestion one by one and re-analyze to watch your rating climb!",
      position: "top",
    },
    {
      target: '[data-tour="strength-toggle"]',
      title: "Show / Hide Password",
      content: "Click this eye icon to reveal or hide your password while typing, so you can see what you're entering without mistyping.",
      position: "left",
    },
  ],

  // ── Password Generator ───────────────────────────────────────────────────
  generator: [
    {
      target: '[data-tour="gen-length"]',
      title: "Set Password Length",
      content: "Drag this slider to choose how many characters your password should have. The color changes from red (too short) to green (ideal length).",
      tip: "For most accounts, 16 characters is ideal. For high-security accounts, go longer.",
      position: "bottom",
    },
    {
      target: '[data-tour="gen-regenerate"]',
      title: "Generate Password",
      content: "Click this button to create a new cryptographically secure random password. Every click generates a completely different result using your browser's crypto API.",
      position: "bottom",
    },
    {
      target: '[data-tour="gen-output"]',
      title: "Your Generated Password",
      content: "Your new password appears here along with SHA-256 and bcrypt hashes — useful if you're a developer who needs to store credentials securely.",
      position: "top",
    },
    {
      target: '[data-tour="gen-copy"]',
      title: "Copy to Clipboard",
      content: "Click this icon to instantly copy the password to your clipboard so you can paste it wherever you need it.",
      tip: "Copy it before switching tabs — generated passwords are not saved anywhere.",
      position: "left",
    },
    {
      target: '[data-tour="gen-options"]',
      title: "Character Types",
      content: "This panel confirms which character types are present: uppercase (A–Z), lowercase (a–z), numbers (0–9), and symbols. All four are always guaranteed in every generated password.",
      position: "top",
    },
  ],

  // ── Input Validator ──────────────────────────────────────────────────────
  validator: [
    {
      target: '[data-tour="val-input"]',
      title: "Fill In All Fields",
      content: "Enter a Full Name, Email, Username, and Message. The backend validates each against its own rules — names allow only letters, emails must have a valid domain, usernames 4–16 chars, etc.",
      tip: "Try pasting '<script>alert(1)</script>' in the message to see it get blocked.",
      position: "bottom",
    },
    {
      target: '[data-tour="val-type"]',
      title: "Validate & Sanitize",
      content: "Click this to send all four fields to the Python backend at once. It runs a two-phase pipeline: sanitization first (stripping dangerous code), then format validation for each field type.",
      position: "bottom",
    },
    {
      target: '[data-tour="val-result"]',
      title: "Validation Status",
      content: "Each field shows a green ✅ (valid) or red ❌ (invalid) badge. If a field fails, the specific error reason appears next to it so you know exactly what to fix.",
      position: "top",
    },
    {
      target: '[data-tour="val-sanitized"]',
      title: "Sanitized Output",
      content: "This panel shows the cleaned version of each field after dangerous characters are removed. This is the safe data you would store in a real database.",
      tip: "Always use sanitized output in your own apps — never store raw user input directly.",
      position: "top",
    },
  ],

  // ── Breach Checker ───────────────────────────────────────────────────────
  breach: [
    {
      target: '[data-tour="breach-tabs"]',
      title: "Two Independent Checkers",
      content: "This tool has two separate tabs that use different APIs. 'Password Check' uses the Have I Been Pwned (HIBP) API. 'Email / Username' uses the XposedOrNot API. Each API checks a different type of credential.",
      tip: "Both are free, require no account, and never expose your real credentials.",
      position: "bottom",
    },
    {
      target: '[data-tour="breach-input"]',
      title: "Enter What to Check",
      content: "Password tab: only the first 5 characters of your password's SHA-1 hash are sent to HIBP — your actual password never leaves your browser (k-anonymity). Email tab: your address is sent to XposedOrNot to look up known breach records.",
      tip: "Your full password is NEVER transmitted — only an anonymous partial hash.",
      position: "bottom",
    },
    {
      target: '[data-tour="breach-submit"]',
      title: "Run the Check",
      content: "Password tab: HIBP returns the number of times that password hash appeared in breach databases. Email tab: XposedOrNot returns a list of every named breach service the address was found in.",
      position: "bottom",
    },
    {
      target: '[data-tour="breach-result"]',
      title: "Breach Result",
      content: "A green shield means no breaches found. A red alert shows the exposure count and risk level (HIBP) or the list of breached services with a timeline (XposedOrNot), plus tailored recommendations.",
      tip: "If your password appeared even once — change it immediately on every site where you use it.",
      position: "top",
    },
  ],

  // ── Port Scanner ─────────────────────────────────────────────────────────
  scanner: [
    {
      target: '[data-tour="agent-setup-panel"]',
      title: "Enable the Local Agent",
      content: "The Port Scanner requires a local agent running on your machine. Download the ZIP, extract it, then run StartAgent.bat (Windows) or StartAgent.sh (Mac/Linux). Once running, paste the agent URL and click Connect.",
      tip: "On Windows, right-click StartAgent.bat and choose Run as Administrator for full scanning support.",
      position: "bottom",
    },
    {
      target: '[data-tour="scan-host"]',
      title: "Enter a Host or IP",
      content: "Type the hostname or IP address of the target you want to scan, e.g. 'localhost', '127.0.0.1', or a domain like 'scanme.nmap.org'. The local agent must be running to perform scans.",
      tip: "Only scan hosts you own or have explicit permission to test. Unauthorized scanning may be illegal.",
      position: "bottom",
    },
    {
      target: '[data-tour="scan-range"]',
      title: "Scan Mode & Port Range",
      content: "Choose how to select ports: 'Common' scans a predefined list of well-known ports (fastest), 'Range' lets you specify start and end ports, and 'Custom' accepts a comma-separated list like 80,443,8080.",
      tip: "Start with 'Common' for a quick overview, then use 'Range' to dig deeper.",
      position: "bottom",
    },
    {
      target: '[data-tour="scan-start"]',
      title: "Start the Scan",
      content: "Click to begin. The local agent performs real TCP connect attempts on each port in parallel and reports whether each one is open, closed, or filtered. Adjust the timeout slider for slow remote hosts.",
      position: "bottom",
    },
    {
      target: '[data-tour="scan-results"]',
      title: "Scan Results",
      content: "Open ports appear here with their port number, detected service name, and a risk badge — High (Telnet/RDP), Medium (SSH/SMTP), Low (HTTP/HTTPS), or Info. Use the filter pills to focus on a specific risk level.",
      position: "top",
    },
  ],

  // ── Traffic Analyzer ─────────────────────────────────────────────────────
  traffic: [
    {
      target: '[data-tour="agent-setup-panel"]',
      title: "Enable the Local Agent",
      content: "Live packet capture requires a local agent running on your machine with elevated privileges. Download the ZIP, extract it, then run StartAgent.bat (Windows) or StartAgent.sh (Mac/Linux). Paste the agent URL and click Connect.",
      tip: "On Mac/Linux run the script with sudo. On Windows right-click StartAgent.bat and choose Run as Administrator — this is required for Scapy to capture packets.",
      position: "bottom",
    },
    {
      target: '[data-tour="traffic-filter"]',
      title: "Filter Your Capture",
      content: "Narrow down which packets to capture before starting. Filter by protocol (TCP, UDP, ICMP), a specific IP address, or separate source and destination IPs. Leave all fields empty to capture everything.",
      tip: "Use the TCP protocol filter to focus on web traffic, or enter your router's IP to monitor gateway activity.",
      position: "bottom",
    },
    {
      target: '[data-tour="traffic-interface"]',
      title: "Capture Duration",
      content: "Drag this slider to set how long the capture runs — from 5 seconds up to 60 seconds. The capture stops automatically when the timer ends, or you can stop it manually at any time.",
      position: "bottom",
    },
    {
      target: '[data-tour="traffic-start"]',
      title: "Start, Stop & Snapshot",
      content: "'Start Live Stream' opens a real-time connection that streams packets as they arrive. 'Snapshot' does a quick 5-second burst. 'Stop' ends the capture. 'Clear' wipes the table.",
      tip: "Use Snapshot for a quick look, and Live Stream when you need to monitor activity over time.",
      position: "top",
    },
    {
      target: '[data-tour="traffic-packets"]',
      title: "Live Packet Table",
      content: "Each captured packet appears here in real time with its timestamp, source/destination IPs and ports, protocol, size, and TCP flags. Suspicious packets (matching known risky ports) are highlighted in orange.",
      tip: "Click Export PCAP to save the capture and open it later in Wireshark for deeper analysis.",
      position: "top",
    },
    {
      target: '[data-tour="traffic-stats"]',
      title: "Traffic Statistics",
      content: "These live counters show a running breakdown of captured traffic by protocol — Total, TCP, UDP, ICMP, and Other — with percentages that update instantly as each new packet arrives.",
      position: "left",
    },
  ],
};