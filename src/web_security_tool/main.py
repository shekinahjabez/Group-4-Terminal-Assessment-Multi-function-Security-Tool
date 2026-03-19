import customtkinter as ctk

from .gui.analyze import StrengthFrame
from .gui.generate import GeneratorFrame
from .gui.validate import ValidatorFrame

from .gui.components.tool_card import ToolCard 


# LIGHT palette (matches your screenshot + React Tailwind)
COLORS = {
    "page_bg": "#f3f7ff",
    "card_active": "#ffffff",
    "card_idle": "#f8fafc",
    "content_bg": "#ffffff",
    "border_idle": "#e2e8f0",
    "border_hover": "#cbd5e1",
    "border_active": "#cbd5e1",
    "text_main": "#1e293b",
    "text_mid": "#334155",
    "text_dim": "#64748b",
    "blue": "#2563eb",
    "emerald": "#059669",
    "indigo": "#4f46e5",
    "bg_dark": "#f8fafc",
    "bg_card": "#ffffff",
    "border": "#e2e8f0",
    "accent": "#2563eb",
    "success": "#10b981",
    "warning": "#f59e0b",
    "danger": "#ef4444",
}


class WebSecurityTool(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SecureKit - Web Security Tool")
        self.geometry("1100x900")
        self.configure(fg_color=COLORS["page_bg"])

        self.active_tab = "strength"
        self.frames = {}
        self.tool_cards = {}  # tool_id -> ToolCard instance

        self._build_ui()
        self._set_active("strength")

    def _build_ui(self):
        self.outer = ctk.CTkFrame(self, fg_color="transparent")
        self.outer.pack(fill="both", expand=True, padx=28, pady=24)

        # Header
        header = ctk.CTkFrame(self.outer, fg_color="transparent")
        header.pack(fill="x", pady=(6, 18))

        ctk.CTkLabel(
            header, text="SecureKit",
            font=("Inter", 44, "bold"),
            text_color=COLORS["text_main"],
        ).pack(anchor="center")

        ctk.CTkLabel(
            header, text="Web Security Tool",
            font=("Inter", 16),
            text_color=COLORS["text_dim"],
        ).pack(anchor="center", pady=(6, 8))

        # Pill badge
        pill = ctk.CTkFrame(
            header,
            fg_color="#ffffff",
            corner_radius=999,
            border_width=1,
            border_color=COLORS["border_idle"],
        )
        pill.pack(anchor="center", pady=(6, 0))

        pill_inner = ctk.CTkFrame(pill, fg_color="transparent")
        pill_inner.pack(padx=14, pady=8)

        ctk.CTkLabel(
            pill_inner, text="●",
            text_color=COLORS["emerald"],
            font=("Inter", 14, "bold"),
        ).pack(side="left")

        ctk.CTkLabel(
            pill_inner,
            text="Client-side • Zero data collection",
            text_color=COLORS["text_dim"],
            font=("Inter", 12, "bold"),
        ).pack(side="left", padx=(8, 0))

        # Tool Cards Grid (3 columns)
        cards_row = ctk.CTkFrame(self.outer, fg_color="transparent")
        cards_row.pack(fill="x", pady=(10, 14))
        cards_row.grid_columnconfigure(0, weight=1)
        cards_row.grid_columnconfigure(1, weight=1)
        cards_row.grid_columnconfigure(2, weight=1)

        tools = [
            {
                "id": "strength",
                "title": "Analyze",
                "subtitle": "Password strength",
                "color": "blue",
                "icon": "src/web_security_tool/gui/assets/icons/eye.png",
            },
            {
                "id": "generator",
                "title": "Generate",
                "subtitle": "Secure password",
                "color": "emerald",
                "icon": "src/web_security_tool/gui/assets/icons/bolt.png",
            },
            {
                "id": "validator",
                "title": "Validate",
                "subtitle": "Form inputs",
                "color": "indigo",
                "icon": "src/web_security_tool/gui/assets/icons/shield.png",
            },
        ]

        for i, tool in enumerate(tools):
            card = ToolCard(
                cards_row,
                tool_id=tool["id"],
                title=tool["title"],
                subtitle=tool["subtitle"],
                icon_path=tool["icon"],
                color_name=tool["color"],
                colors=COLORS,
                on_click=self._set_active,
                tint_bg_for=self._tint_bg_for,
                accent_for=self._accent_for,
            )
            card.grid(row=0, column=i, sticky="ew", padx=10)
            self.tool_cards[tool["id"]] = card

        # Content Area
        self.content_card = ctk.CTkFrame(
            self.outer,
            fg_color=COLORS["content_bg"],
            corner_radius=18,
            border_width=1,
            border_color=COLORS["border_idle"],
        )
        self.content_card.pack(fill="both", expand=True, pady=(6, 10))

        self.content_inner = ctk.CTkFrame(self.content_card, fg_color="transparent")
        self.content_inner.pack(fill="both", expand=True, padx=24, pady=24)

        # Footer
        footer = ctk.CTkFrame(self.outer, fg_color="transparent")
        footer.pack(fill="x", pady=(6, 2))
        ctk.CTkLabel(
            footer,
            text="Group 4\nMO-IT142 - Security Script Programming",
            text_color=COLORS["text_dim"],
            font=("Inter", 12),
            justify="center",
        ).pack(anchor="center")


    def _accent_for(self, color_name: str) -> str:
        return COLORS["blue"] if color_name == "blue" else COLORS["emerald"] if color_name == "emerald" else COLORS["indigo"]

    def _tint_bg_for(self, color_name: str, active: bool) -> str:
        if not active:
            return "#f1f5f9"  # slate-100 (idle)
        if color_name == "blue":
            return "#dbeafe"  # blue-100
        if color_name == "emerald":
            return "#d1fae5"  # emerald-100
        return "#e0e7ff"      # indigo-100

    def _set_active(self, tab_id: str):
        self.active_tab = tab_id

        # Update tool cards UI
        for tid, card in self.tool_cards.items():
            card.set_active(tid == tab_id)

        # Swap content frames
        for child in self.content_inner.winfo_children():
            child.pack_forget()

        if tab_id not in self.frames:
            if tab_id == "strength":
                self.frames[tab_id] = StrengthFrame(self.content_inner, COLORS)
            elif tab_id == "generator":
                self.frames[tab_id] = GeneratorFrame(self.content_inner, COLORS)
            elif tab_id == "validator":
                self.frames[tab_id] = ValidatorFrame(self.content_inner, COLORS)
            else:
                raise ValueError(f"Unknown tab: {tab_id}")

        self.frames[tab_id].pack(fill="both", expand=True)


if __name__ == "__main__":
    ctk.set_appearance_mode("light")
    app = WebSecurityTool()
    app.mainloop()
