"""Port Scanner - Tkinter GUI module."""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
import sys
from datetime import datetime

#sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PortScanner.core.scanner import (
    ScanEngine, validate_hostname, validate_port_range, WELL_KNOWN_PORTS,
)

# Color scheme (matching NetworkTrafficAnalyzer template)
PRIMARY_COLOR = "#007bff"
PRIMARY_HOVER = "#0056b3"
BG_COLOR = "#f5f5f5"
WHITE = "#ffffff"
TEXT_COLOR = "#333333"
HEADER_BG = "#1a1a2e"
HEADER_FG = "#ffffff"
SUCCESS_GREEN = "#28a745"
ERROR_RED = "#dc3545"
WARNING_YELLOW = "#ffc107"


class PortScannerApp:
    #"""Main application window."""

    def __init__(self, root, parent=None):
        self.root = root
        self.parent = parent if parent else root

        # Only configure the window in standalone mode
        if self.parent == self.root:
            self.root.title("Port Scanner - Portable Edition")
            self.root.geometry("960x720")
            self.root.minsize(760, 560)
            self.root.configure(bg=BG_COLOR)

        self.engine = ScanEngine()
        self.port_count = {"Open": 0, "Closed": 0, "Total": 0}

        # Resolve data directory
        self.data_dir = os.environ.get("PS_DATA_DIR", "")
        if not self.data_dir:
            portable_root = os.path.dirname(
                os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                )
            )
            self.data_dir = os.path.join(portable_root, "Data")

        self.log_dir = os.path.join(self.data_dir, "logs")
        os.makedirs(self.log_dir, exist_ok=True)

        self._build_ui()

        # Only hook close button in standalone mode
        if self.parent == self.root:
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    
    #def _build_ui(self):
        #self._build_header()
        #self._build_input_section()
        #self._build_controls()
        #self._build_display()
        #self._build_stats()
        #self._build_footer()

    def _build_ui(self):
        if self.parent == self.root:
            self._build_header()

        self._build_input_section()
        self._build_controls()
        self._build_display()
        self._build_stats()

        if self.parent == self.root:
            self._build_footer()

    def _build_header(self):
        header = tk.Frame(self.parent, bg=HEADER_BG, pady=16)
        header.pack(fill=tk.X)

        tk.Label(
            header, text="Network Port Scanner",
            font=("Helvetica", 22, "bold"), bg=HEADER_BG, fg=HEADER_FG,
        ).pack()

        tk.Label(
            header, text="TCP Port Scanning \u2022 Portable Edition",
            font=("Helvetica", 11), bg=HEADER_BG, fg="#aaaaaa",
        ).pack()

    def _build_input_section(self):
        section = tk.Frame(self.parent, bg=WHITE, padx=24, pady=16)
        section.pack(fill=tk.X, padx=24, pady=(16, 4))

        tk.Label(
            section, text="Scan Configuration",
            font=("Helvetica", 14, "bold"), bg=WHITE, fg=TEXT_COLOR, anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            section,
            text="Enter a target host and port range to scan. "
                 "Results are displayed in real-time.",
            font=("Helvetica", 10), bg=WHITE, fg="#666666", anchor="w",
        ).pack(fill=tk.X, pady=(0, 12))

        # Row 1: Target Host
        row1 = tk.Frame(section, bg=WHITE)
        row1.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            row1, text="Target Host:",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.host_var = tk.StringVar()
        tk.Entry(
            row1, textvariable=self.host_var, width=30,
            font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row1, text="(e.g., 127.0.0.1 or scanme.nmap.org)",
            font=("Helvetica", 9), bg=WHITE, fg="#999999",
        ).pack(side=tk.LEFT)

        # Row 2: Port Range
        row2 = tk.Frame(section, bg=WHITE)
        row2.pack(fill=tk.X)

        tk.Label(
            row2, text="Start Port:",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.start_port_var = tk.StringVar(value="1")
        tk.Entry(
            row2, textvariable=self.start_port_var, width=8,
            font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1,
        ).pack(side=tk.LEFT, padx=(0, 16))

        tk.Label(
            row2, text="End Port:",
            font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.end_port_var = tk.StringVar(value="1024")
        tk.Entry(
            row2, textvariable=self.end_port_var, width=8,
            font=("Helvetica", 10), relief=tk.SOLID, borderwidth=1,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            row2, text="(1\u201365535)",
            font=("Helvetica", 9), bg=WHITE, fg="#999999",
        ).pack(side=tk.LEFT)

    def _build_controls(self):
        section = tk.Frame(self.parent, bg=BG_COLOR, pady=8)
        section.pack(fill=tk.X, padx=24)

        btn_frame = tk.Frame(section, bg=BG_COLOR)
        btn_frame.pack()

        self.scan_btn = tk.Button(
            btn_frame, text="Start Scan", font=("Helvetica", 11, "bold"),
            bg=PRIMARY_COLOR, fg=WHITE, activebackground=PRIMARY_HOVER,
            activeforeground=WHITE, relief=tk.FLAT, padx=20, pady=6,
            cursor="hand2", command=self._start_scan,
        )
        self.scan_btn.pack(side=tk.LEFT, padx=6)

        self.stop_btn = tk.Button(
            btn_frame, text="Stop Scan", font=("Helvetica", 11, "bold"),
            bg=ERROR_RED, fg=WHITE, activebackground="#a71d2a",
            activeforeground=WHITE, relief=tk.FLAT, padx=20, pady=6,
            cursor="hand2", state=tk.DISABLED, command=self._stop_scan,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=6)

        self.clear_btn = tk.Button(
            btn_frame, text="Clear Results", font=("Helvetica", 11),
            bg=WARNING_YELLOW, fg=TEXT_COLOR, activebackground="#e0a800",
            activeforeground=TEXT_COLOR, relief=tk.FLAT, padx=20, pady=6,
            cursor="hand2", command=self._clear_results,
        )
        self.clear_btn.pack(side=tk.LEFT, padx=6)

        self.export_btn = tk.Button(
            btn_frame, text="Export Log", font=("Helvetica", 11),
            bg=SUCCESS_GREEN, fg=WHITE, activebackground="#1e7e34",
            activeforeground=WHITE, relief=tk.FLAT, padx=20, pady=6,
            cursor="hand2", command=self._export_log,
        )
        self.export_btn.pack(side=tk.LEFT, padx=6)

    def _build_display(self):
        section = tk.Frame(self.parent, bg=WHITE, padx=24, pady=16)
        section.pack(fill=tk.BOTH, expand=True, padx=24, pady=(4, 4))

        tk.Label(
            section, text="Scan Results",
            font=("Helvetica", 14, "bold"), bg=WHITE, fg=TEXT_COLOR, anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        self.output_text = scrolledtext.ScrolledText(
            section, wrap=tk.WORD, font=("Consolas", 9),
            bg="#1e1e1e", fg="#d4d4d4", insertbackground=WHITE,
            relief=tk.FLAT, borderwidth=0, state=tk.DISABLED,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Result color tags
        self.output_text.tag_configure("open", foreground="#4ec9b0")
        self.output_text.tag_configure("closed", foreground="#569cd6")
        self.output_text.tag_configure("error", foreground="#f44747")
        self.output_text.tag_configure("info", foreground="#608b4e")
        self.output_text.tag_configure("summary", foreground="#dcdcaa")

    def _build_stats(self):
        section = tk.Frame(self.parent, bg=WHITE, padx=24, pady=10)
        section.pack(fill=tk.X, padx=24, pady=(0, 4))

        self.stats_labels = {}
        stats_frame = tk.Frame(section, bg=WHITE)
        stats_frame.pack()

        for key in ("Total", "Open", "Closed"):
            lbl = tk.Label(
                stats_frame, text=f"{key}: 0",
                font=("Helvetica", 10, "bold"), bg=WHITE, fg=TEXT_COLOR, padx=16,
            )
            lbl.pack(side=tk.LEFT)
            self.stats_labels[key] = lbl

    def _build_footer(self):
        footer = tk.Frame(self.parent, bg=HEADER_BG, pady=8)
        footer.pack(fill=tk.X, side=tk.BOTTOM)

        tk.Label(
            footer, text="Group 4 \u2022 MO-IT142 - Security Script Programming",
            font=("Helvetica", 9), bg=HEADER_BG, fg="#888888",
        ).pack()

    def _start_scan(self):
        host = self.host_var.get()
        start_str = self.start_port_var.get()
        end_str = self.end_port_var.get()

        # Validate hostname
        valid_host, result = validate_hostname(host)
        if not valid_host:
            messagebox.showerror("Validation Error", result)
            return
        resolved_ip = result

        # Validate port range
        valid_range, start_port, end_port, err = validate_port_range(start_str, end_str)
        if not valid_range:
            messagebox.showerror("Validation Error", err)
            return

        # Reset counters and output
        self.port_count = {"Open": 0, "Closed": 0, "Total": 0}
        self._update_stats()
        self._clear_output()

        # Display scan header
        display_host = host.strip()
        if resolved_ip != display_host:
            header_line = f"Scanning host: {display_host} ({resolved_ip})"
        else:
            header_line = f"Scanning host: {resolved_ip}"
        self._append_output(
            f"{header_line}\n"
            f"Port range: {start_port}\u2013{end_port}\n"
            f"{'=' * 50}\n",
            tag="info",
        )

        # Toggle buttons
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        # Start scan
        try:
            self.engine.start(
                host=resolved_ip,
                start_port=start_port,
                end_port=end_port,
                callback=self._on_result,
            )
        except RuntimeError as e:
            messagebox.showerror("Scan Error", str(e))
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def _stop_scan(self):
        self.engine.stop()
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def _on_result(self, port, is_open, line):
        """Thread-safe callback: schedule GUI update on main thread."""
        self.root.after(0, self._display_result, port, is_open, line)

    def _display_result(self, port, is_open, line):
        if line.startswith("[INFO]") or line.startswith("\n="):
            tag = "summary" if line.startswith("\n=") else "info"
            self._append_output(line + "\n", tag=tag)
            # Re-enable buttons when scan finishes
            if not self.engine.running:
                self.scan_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
            return

        if line.startswith("[ERROR]"):
            self._append_output(line + "\n", tag="error")
            if not self.engine.running:
                self.scan_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
            return

        # Normal port result
        tag = "open" if is_open else "closed"
        self._append_output(line + "\n", tag=tag)

        self.port_count["Total"] += 1
        if is_open:
            self.port_count["Open"] += 1
        else:
            self.port_count["Closed"] += 1
        self._update_stats()

        # Re-enable buttons when scan finishes
        if not self.engine.running:
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def _append_output(self, text, tag=None):
        self.output_text.config(state=tk.NORMAL)
        if tag:
            self.output_text.insert(tk.END, text, tag)
        else:
            self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def _clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)

    def _clear_results(self):
        """Clear the output display and reset statistics."""
        self._clear_output()
        self.port_count = {"Open": 0, "Closed": 0, "Total": 0}
        self._update_stats()

    def _update_stats(self):
        for key, label in self.stats_labels.items():
            label.config(text=f"{key}: {self.port_count[key]}")

    def _export_log(self):
        """Save scan output to Data/logs/."""
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Export", "Nothing to export yet.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{timestamp}.log"
        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        messagebox.showinfo("Export Successful", f"Log saved to:\n{filepath}")

    def _on_close(self):
        if self.engine.running:
            self.engine.stop()
        self.root.destroy()

    def shutdown(self):
        if self.engine.running:
            self.engine.stop()    


def main():
    root = tk.Tk()
    PortScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
