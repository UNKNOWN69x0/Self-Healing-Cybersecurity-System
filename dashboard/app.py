import customtkinter as ctk
from theme import COLORS, FONTS
from agent_control import is_agent_running, start_agent, stop_agent
from log_reader import read_last_logs

ctk.set_appearance_mode("dark")


class SHCSDashboard(ctk.CTk):

    def __init__(self):
        super().__init__()

        self._notifications_enabled = True
        self._threat_count = 0

        self.title("Self-Healing Cybersecurity System")
        self.geometry("920x680")
        self.resizable(False, False)

        header = ctk.CTkLabel(
            self,
            text="Self-Healing Cybersecurity System",
            font=FONTS["title"],
            text_color=COLORS["accent"]
        )
        header.pack(pady=(20, 10))

        self.status_label = ctk.CTkLabel(
            self,
            text="Status: Checking...",
            font=FONTS["subtitle"]
        )
        self.status_label.pack(pady=(0, 5))

        # --- System Status row ---
        status_row = ctk.CTkFrame(self, fg_color=COLORS["panel"])
        status_row.pack(pady=5, fill="x", padx=20)

        self.ml_status_label = ctk.CTkLabel(
            status_row,
            text="ML: Learning (0/20 samples)",
            font=FONTS["small"],
            text_color=COLORS.get("warning", "#FFA500"),
        )
        self.ml_status_label.grid(row=0, column=0, padx=15, pady=8, sticky="w")

        self.threat_count_label = ctk.CTkLabel(
            status_row,
            text="Threats detected: 0",
            font=FONTS["small"],
        )
        self.threat_count_label.grid(row=0, column=1, padx=15, pady=8)

        self.notif_btn = ctk.CTkButton(
            status_row,
            text="🔔 Notifications: ON",
            width=160,
            fg_color=COLORS["success"],
            command=self._toggle_notifications,
        )
        self.notif_btn.grid(row=0, column=2, padx=15, pady=8)

        # --- Controls ---
        controls = ctk.CTkFrame(self, fg_color=COLORS["panel"])
        controls.pack(pady=10)

        ctk.CTkButton(
            controls,
            text="Start Agent",
            width=150,
            fg_color=COLORS["success"],
            command=self.start_agent
        ).grid(row=0, column=0, padx=15, pady=15)

        ctk.CTkButton(
            controls,
            text="Stop Agent",
            width=150,
            fg_color=COLORS["danger"],
            command=self.stop_agent
        ).grid(row=0, column=1, padx=15, pady=15)

        log_label = ctk.CTkLabel(
            self,
            text="Live Agent Logs",
            font=FONTS["subtitle"]
        )
        log_label.pack(pady=(20, 5))

        self.log_box = ctk.CTkTextbox(
            self,
            width=880,
            height=300,
            font=FONTS["small"],
            state="disabled"
        )
        self.log_box.pack(pady=(0, 15))

        self.refresh()

    def _toggle_notifications(self):
        self._notifications_enabled = not self._notifications_enabled
        if self._notifications_enabled:
            self.notif_btn.configure(text="🔔 Notifications: ON", fg_color=COLORS["success"])
        else:
            self.notif_btn.configure(text="🔕 Notifications: OFF", fg_color=COLORS["danger"])

    def start_agent(self):
        start_agent()
        self.refresh_status()

    def stop_agent(self):
        stop_agent()
        self.refresh_status()

    def refresh_status(self):
        if is_agent_running():
            self.status_label.configure(
                text="Status: RUNNING",
                text_color=COLORS["success"]
            )
        else:
            self.status_label.configure(
                text="Status: STOPPED",
                text_color=COLORS["danger"]
            )

    def _refresh_ml_status(self, logs):
        """Parse ML status and threat count from log lines."""
        ml_line = None
        threat_count = 0
        for line in reversed(logs.splitlines()):
            if ml_line is None and "ML status:" in line:
                ml_line = line
            if "Threat detected:" in line:
                threat_count += 1
        self._threat_count = threat_count
        self.threat_count_label.configure(text=f"Threats detected: {threat_count}")

        if ml_line:
            if "'mode': 'learning'" in ml_line or "\"mode\": \"learning\"" in ml_line:
                try:
                    import re
                    m = re.search(r"'samples': (\d+).*'min_samples': (\d+)", ml_line)
                    if m:
                        s, ms = m.group(1), m.group(2)
                        self.ml_status_label.configure(
                            text=f"ML: Learning ({s}/{ms} samples)",
                            text_color=COLORS.get("warning", "#FFA500"),
                        )
                        return
                except Exception:
                    pass
                self.ml_status_label.configure(
                    text="ML: Learning",
                    text_color=COLORS.get("warning", "#FFA500"),
                )
            elif "'mode': 'active'" in ml_line or "\"mode\": \"active\"" in ml_line:
                self.ml_status_label.configure(
                    text="ML: Active — Monitoring",
                    text_color=COLORS["success"],
                )

    def refresh_logs(self):
        scroll_pos = self.log_box.yview()

        logs = read_last_logs()

        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.insert("1.0", logs)
        self.log_box.configure(state="disabled")

        self.log_box.yview_moveto(scroll_pos[0])
        self._refresh_ml_status(logs)

    def refresh(self):
        self.refresh_status()
        self.refresh_logs()
        self.after(3000, self.refresh)


if __name__ == "__main__":
    app = SHCSDashboard()
    app.mainloop()
