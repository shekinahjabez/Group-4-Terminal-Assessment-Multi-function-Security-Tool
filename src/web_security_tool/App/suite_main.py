import os
import sys
import tkinter as tk
from tkinter import ttk

# --- Paths / Portable Data ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))          # .../App
PORTABLE_ROOT = os.path.dirname(APP_DIR)                     # .../Milestone2_Local_Security_Tool
DATA_DIR = os.path.join(PORTABLE_ROOT, "Data")
LOG_DIR = os.path.join(DATA_DIR, "logs")
SETTINGS_DIR = os.path.join(DATA_DIR, "settings")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(SETTINGS_DIR, exist_ok=True)

os.environ["NTA_DATA_DIR"] = DATA_DIR
os.environ["NTA_LOG_DIR"] = LOG_DIR

# Make App/ importable (so we can import NetworkTrafficAnalyzer and PortScanner)
sys.path.insert(0, APP_DIR)

from NetworkTrafficAnalyzer.gui.app import NetworkTrafficAnalyzerApp
from PortScanner.gui.app import PortScannerApp


BG_COLOR = "#f5f5f5"
HEADER_BG = "#1a1a2e"
HEADER_FG = "#ffffff"


class NetworkSuiteApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Network Tools Suite - Portable Edition")
        self.root.geometry("960x720")
        self.root.minsize(760, 560)
        self.root.configure(bg=BG_COLOR)

        self._build_header()

        container = tk.Frame(self.root, bg=BG_COLOR)
        container.pack(fill=tk.BOTH, expand=True, padx=24, pady=(16, 4))

        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)

        traffic_frame = tk.Frame(notebook, bg=BG_COLOR)
        scanner_frame = tk.Frame(notebook, bg=BG_COLOR)

        notebook.add(traffic_frame, text="Traffic Analyzer")
        notebook.add(scanner_frame, text="Port Scanner")

        # Mount both tabs
        self.traffic_tab = NetworkTrafficAnalyzerApp(self.root, traffic_frame)
        self.scanner_tab = PortScannerApp(self.root, scanner_frame)
        #self.traffic_tab = NetworkTrafficAnalyzerApp(traffic_frame, parent=self.root)
        #self.scanner_tab = PortScannerApp(scanner_frame, parent=self.root)

        self._build_footer()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_header(self):
        header = tk.Frame(self.root, bg=HEADER_BG, pady=16)
        header.pack(fill=tk.X)
        tk.Label(
            header, text="Network Tools Suite",
            font=("Helvetica", 22, "bold"), bg=HEADER_BG, fg=HEADER_FG,
        ).pack()
        tk.Label(
            header, text="Traffic Analyzer • Port Scanner • Portable Edition",
            font=("Helvetica", 11), bg=HEADER_BG, fg="#aaaaaa",
        ).pack()

    def _build_footer(self):
        footer = tk.Frame(self.root, bg=HEADER_BG, pady=8)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(
            footer, text="Group 4 • MO-IT142 - Security Script Programming",
            font=("Helvetica", 9), bg=HEADER_BG, fg="#888888",
        ).pack()

    def _on_close(self):
        # Stop engines safely
        self.traffic_tab.shutdown()
        self.scanner_tab.shutdown()
        self.root.destroy()


def main():
    root = tk.Tk()
    NetworkSuiteApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
