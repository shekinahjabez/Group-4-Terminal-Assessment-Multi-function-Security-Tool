"""NetworkTraffic Analyzer - Tkinter GUI module."""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import shutil
import os
import sys
from datetime import datetime

#sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from NetworkTrafficAnalyzer.core.sniffer import CaptureEngine, SCAPY_AVAILABLE

# Color scheme
PRIMARY_COLOR = "#007bff"
PRIMARY_HOVER = "#0056b3"
BG_COLOR = "#f5f5f5"
WHITE = "#ffffff"
TEXT_COLOR = "#333333"
LIGHT_GRAY = "#e0e0e0"
HEADER_BG = "#1a1a2e"
HEADER_FG = "#ffffff"
SUCCESS_GREEN = "#28a745"
ERROR_RED = "#dc3545"
WARNING_YELLOW = "#ffc107"


class NetworkTrafficAnalyzerApp:
    """Main application window."""

    def __init__(self, root, parent=None):
        self.root = root
        self.parent = parent if parent else root

        # Only configure the window in standalone mode
        if self.parent == self.root:
            self.root.title("NetworkTraffic Analyzer - Portable Edition")
            self.root.geometry("960x720")
            self.root.minsize(760, 560)
            self.root.configure(bg=BG_COLOR)

        self.engine = CaptureEngine(os.environ.get("NTA_LOG_DIR", "logs"))
        self.session_active = False
        self.had_capture = False        # <-- IMPORTANT (you referenced this later)
        self.log_exported = True        # nothing to export yet
        self.last_pcap_path = ""        # set after Stop

        self.log_dir = os.environ.get("NTA_LOG_DIR", "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        ...
        self.packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self._build_ui()
        self._check_scapy()

        # Only hook close button in standalone mode
        if self.parent == self.root:
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)


    def _build_ui(self):
        if self.parent == self.root:
            self._build_header()

        self._build_filter_section()
        self._build_controls()
        self._build_stats()
        self._build_display()

        if self.parent == self.root:
            self._build_footer()

    def _build_header(self):
        header = tk.Frame(self.parent, bg=HEADER_BG, pady=16)
        header.pack(fill=tk.X)

        tk.Label(
            header, text="NetworkTraffic Analyzer",
            font=("Helvetica", 22, "bold"), bg=HEADER_BG, fg=HEADER_FG,
        ).pack()

        tk.Label(
            header, text="Real-Time Packet Capture \u2022 Portable Edition",
            font=("Helvetica", 11), bg=HEADER_BG, fg="#aaaaaa",
        ).pack()

    def _build_filter_section(self):
        section = tk.Frame(self.parent, bg=WHITE, padx=24, pady=16)
        section.pack(fill=tk.X, padx=24, pady=(16, 4))

        tk.Label(
            section, text="Capture Filters",
            font=("Helvetica", 14, "bold"), bg=WHITE, fg=TEXT_COLOR, anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            section,
            text="Select a protocol and/or port to filter traffic. "
                 "Leave blank to capture all packets.",
            font=("Helvetica", 10), bg=WHITE, fg="#666666", anchor="w",
        ).pack(fill=tk.X, pady=(0, 12))

        input_frame = tk.Frame(section, bg=WHITE)
        input_frame.pack(fill=tk.X)

        tk.Label(
            input_frame, text="Protocol:",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.protocol_var = tk.StringVar(value="All")
        ttk.Combobox(
            input_frame, textvariable=self.protocol_var,
            values=["All", "TCP", "UDP", "ICMP"], state="readonly", width=10,
        ).pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(
            input_frame, text="Port:",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.port_var = tk.StringVar()
        tk.Entry(
            input_frame, textvariable=self.port_var, width=10,
            font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1,
        ).pack(side=tk.LEFT)

        # ---- IP filters row ----
        ip_row = tk.Frame(section, bg=WHITE)
        ip_row.pack(fill=tk.X, pady=(12, 0))

        tk.Label(
            ip_row, text="IP (any):",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.ip_any_var = tk.StringVar()
        tk.Entry(
            ip_row, textvariable=self.ip_any_var, width=18,
            font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1,
        ).pack(side=tk.LEFT, padx=(0, 16))

        tk.Label(
            ip_row, text="Source IP:",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.src_ip_var = tk.StringVar()
        tk.Entry(
            ip_row, textvariable=self.src_ip_var, width=18,
            font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1,
        ).pack(side=tk.LEFT, padx=(0, 16))

        tk.Label(
            ip_row, text="Destination IP:",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.dst_ip_var = tk.StringVar()
        tk.Entry(
            ip_row, textvariable=self.dst_ip_var, width=18,
            font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1,
        ).pack(side=tk.LEFT)

    def _build_controls(self):
        section = tk.Frame(self.parent, bg=BG_COLOR, pady=8)
        section.pack(fill=tk.X, padx=24)

        btn_frame = tk.Frame(section, bg=BG_COLOR)
        btn_frame.pack()

        self.start_btn = tk.Button(
            btn_frame, text="Start Capture", font=("Helvetica", 11, "bold"),
            bg=PRIMARY_COLOR, fg=WHITE, activebackground=PRIMARY_HOVER,
            activeforeground=WHITE, relief=tk.FLAT, padx=20, pady=6,
            cursor="hand2", command=self._start_capture,
        )
        self.start_btn.pack(side=tk.LEFT, padx=6)

        self.stop_btn = tk.Button(
            btn_frame, text="Stop Capture", font=("Helvetica", 11, "bold"),
            bg=ERROR_RED, fg=WHITE, activebackground="#a71d2a",
            activeforeground=WHITE, relief=tk.FLAT, padx=20, pady=6,
            cursor="hand2", state=tk.DISABLED, command=self._stop_capture,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=6)

        self.export_btn = tk.Button(
            btn_frame, text="Export Log", font=("Helvetica", 11),
            bg=SUCCESS_GREEN, fg=WHITE, activebackground="#1e7e34",
            activeforeground=WHITE, relief=tk.FLAT, padx=20, pady=6,
            cursor="hand2", command=self._export_log,
        )
        self.export_btn.pack(side=tk.LEFT, padx=6)

        self.export_btn.config(state=tk.DISABLED)

    def _build_display(self):
        section = tk.Frame(self.parent, bg=WHITE, padx=24, pady=16)
        section.pack(fill=tk.BOTH, expand=True, padx=24, pady=(4, 4))

        tk.Label(
            section, text="Live Packet Feed",
            font=("Helvetica", 14, "bold"), bg=WHITE, fg=TEXT_COLOR, anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        self.output_text = scrolledtext.ScrolledText(
            section, wrap=tk.WORD, font=("Consolas", 9),
            bg="#1e1e1e", fg="#d4d4d4", insertbackground=WHITE,
            relief=tk.FLAT, borderwidth=0, state=tk.DISABLED,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Protocol color tags
        self.output_text.tag_configure("tcp", foreground="#569cd6")
        self.output_text.tag_configure("udp", foreground="#4ec9b0")
        self.output_text.tag_configure("icmp", foreground="#ce9178")
        self.output_text.tag_configure("error", foreground="#f44747")
        self.output_text.tag_configure("info", foreground="#608b4e")

    def _build_stats(self):
        section = tk.Frame(self.parent, bg=WHITE, padx=24, pady=10)
        section.pack(fill=tk.X, padx=24, pady=(0, 4))

        self.stats_labels = {}
        stats_frame = tk.Frame(section, bg=WHITE)
        stats_frame.pack()

        for proto in ("TCP", "UDP", "ICMP", "Other"):
            lbl = tk.Label(
                stats_frame, text=f"{proto}: 0",
                font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR, padx=16,
            )
            lbl.pack(side=tk.LEFT)
            self.stats_labels[proto] = lbl

    def _build_footer(self):
        footer = tk.Frame(self.parent, bg=HEADER_BG, pady=8)
        footer.pack(fill=tk.X, side=tk.BOTTOM)

        tk.Label(
            footer, text="Group 4 \u2022 MO-IT142 - Security Script Programming",
            font=("Helvetica", 9), bg=HEADER_BG, fg="#888888",
        ).pack()

    def _check_scapy(self):
        if not SCAPY_AVAILABLE:
            self._append_output(
                "[WARNING] Scapy is not installed.\n"
                "Install it with:  pip install scapy\n"
                "Then restart the application.\n",
                tag="error",
            )

    def _start_capture(self):
        protocol = self.protocol_var.get()
        if protocol == "All":
            protocol = ""

        port = self.port_var.get().strip()
        ip_any = self.ip_any_var.get().strip()
        src_ip = self.src_ip_var.get().strip()
        dst_ip = self.dst_ip_var.get().strip()

        try:
            self.engine.start(
                protocol=protocol.lower(),
                port=port,
                ip=ip_any,
                src_ip=src_ip,
                dst_ip=dst_ip,
                callback=self._on_packet,
            )
        except (RuntimeError, ValueError) as e:
            messagebox.showerror("Filter Error", str(e))
            return

        self.session_active = True
        self.had_capture = True
        self.log_exported = False

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)

        filter_desc = (
            f"Protocol={protocol or 'All'}, Port={port or 'Any'}, "
            f"IP={ip_any or 'Any'}, SRC={src_ip or 'Any'}, DST={dst_ip or 'Any'}"
        )
        self._append_output(f"Capture started... ({filter_desc})\n", tag="info")

    def _stop_capture(self):
        self.engine.stop()

        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        self.session_active = False

        # Enable export AFTER stopping
        self.export_btn.config(state=tk.NORMAL)

        self._append_output("Capture stopped. Click 'Export Log' to save results.\n", tag="info")

    def _on_packet(self, line):
        """Thread-safe callback: schedule GUI update on main thread."""
        self.root.after(0, self._display_packet, line)

    def _display_packet(self, line):
        tag = "tcp"
        if "UDP" in line:
            tag = "udp"
        elif "ICMP" in line:
            tag = "icmp"
        elif "[ERROR]" in line:
            tag = "error"

        for proto in ("TCP", "UDP", "ICMP"):
            if proto in line:
                self.packet_count[proto] += 1
                break
        else:
            if "[ERROR]" not in line and "[WARNING]" not in line:
                self.packet_count["Other"] += 1

        self._append_output(line + "\n", tag=tag)
        self._update_stats()

    def _append_output(self, text, tag=None):
        self.output_text.config(state=tk.NORMAL)
        if tag:
            self.output_text.insert(tk.END, text, tag)
        else:
            self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def _update_stats(self):
        for proto, label in self.stats_labels.items():
            label.config(text=f"{proto}: {self.packet_count[proto]}")

    def _export_log(self):
        """Export BOTH: (1) text log and (2) pcap into logs/."""
        if self.engine.running:
            messagebox.showwarning("Export", "Stop the capture before exporting.")
            return

        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Export", "Nothing to export yet.")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 1) Save LOG text
        log_name = f"capture_{ts}.log"
        log_path = os.path.join(self.log_dir, log_name)
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(content + "\n")

        # 2) Save PCAP (ONLY NOW)
        pcap_note = "No packets captured, so no PCAP was created."
        try:
            pcap_path = ""
            if hasattr(self.engine, "export_pcap"):
                pcap_path = self.engine.export_pcap(self.log_dir)

            if pcap_path and os.path.isfile(pcap_path):
                pcap_note = f"PCAP saved to:\n{pcap_path}"
        except Exception as e:
            pcap_note = f"PCAP export failed: {e}"

        self.log_exported = True
        self.export_btn.config(state=tk.DISABLED)

        messagebox.showinfo(
            "Export Successful",
            f"Log saved to:\n{log_path}\n\n{pcap_note}"
        )
        self._append_output(f"[INFO] Exported log: {log_path}\n", tag="info")
        if pcap_note.startswith("PCAP saved to:"):
            self._append_output(f"[INFO] {pcap_note}\n", tag="info")

    def _on_close(self):
        if self.engine.running:
            messagebox.showwarning("Capture Running", "Stop the capture before exiting.")
            return

        if self.had_capture and not self.log_exported:
            messagebox.showwarning(
                "Unsaved Session",
                "You captured traffic but haven't exported yet.\n\n"
                "Click 'Export Log' to save to Data/logs before exiting."
            )
            return

        self.root.destroy()

    def shutdown(self):
        if self.engine.running:
            self.engine.stop()


def main():
    root = tk.Tk()
    NetworkTrafficAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
