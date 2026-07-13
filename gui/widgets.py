import customtkinter as ctk


class DeviceCard(ctk.CTkFrame):
    def __init__(self, master, device_info, **kwargs):
        super().__init__(master, **kwargs)

        self.configure(corner_radius=8, border_width=1, border_color=("#D0D0D0", "#404040"))

        self.device_info = device_info
        self.expanded = False
        self.detail_frame = None

        self._build_header()

    def _build_header(self):
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=10, pady=(8, 4))

        device_type = self.device_info.get("device_type", "Unknown")
        ip = self.device_info.get("ip", "?")
        confidence = self.device_info.get("confidence", "Low")

        confidence_colors = {
            "High": "#2ECC71",
            "Medium": "#F1C40F",
            "Low": "#E74C3C",
        }
        conf_color = confidence_colors.get(confidence, "#95A5A6")

        type_icon = self._get_type_icon(device_type)

        self.type_label = ctk.CTkLabel(
            self.header_frame,
            text=f"{type_icon} {device_type}",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        self.type_label.pack(side="left", padx=(0, 10))

        self.ip_label = ctk.CTkLabel(
            self.header_frame,
            text=f"IP: {ip}",
            font=ctk.CTkFont(size=12),
            text_color=("#555555", "#AAAAAA"),
        )
        self.ip_label.pack(side="left", padx=5)

        self.conf_label = ctk.CTkLabel(
            self.header_frame,
            text=confidence,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=conf_color,
        )
        self.conf_label.pack(side="right", padx=5)

        self._build_info_section()

    def _build_info_section(self):
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.pack(fill="x", padx=10, pady=(0, 8))

        mac = self.device_info.get("mac", "?")
        vendor = self.device_info.get("vendor", "Unknown")
        os_val = self.device_info.get("os", "Unknown")

        details = self.device_info.get("details", [])
        detail_text = " | ".join(details) if details else "No additional info"

        row1 = ctk.CTkFrame(info_frame, fg_color="transparent")
        row1.pack(fill="x")

        ctk.CTkLabel(
            row1,
            text=f"MAC: {mac}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=("#444444", "#BBBBBB"),
        ).pack(side="left", padx=(0, 15))

        ctk.CTkLabel(
            row1,
            text=f"Vendor: {vendor}",
            font=ctk.CTkFont(size=11, weight="bold"),
        ).pack(side="left", padx=(0, 15))

        ctk.CTkLabel(
            row1,
            text=f"OS: {os_val}",
            font=ctk.CTkFont(size=11),
            text_color=("#555555", "#AAAAAA"),
        ).pack(side="left")

        row2 = ctk.CTkFrame(info_frame, fg_color="transparent")
        row2.pack(fill="x", pady=(4, 0))

        ctk.CTkLabel(
            row2,
            text=detail_text,
            font=ctk.CTkFont(size=10),
            text_color=("#777777", "#888888"),
            wraplength=500,
            justify="left",
        ).pack(side="left")

    def _get_type_icon(self, device_type: str) -> str:
        dt = device_type.lower()
        if "router" in dt or "gateway" in dt:
            return "\U0001F3E1"
        if "phone" in dt or "smartphone" in dt or "mobile" in dt:
            return "\U0001F4F1"
        if "laptop" in dt or "desktop" in dt:
            return "\U0001F4BB"
        if "camera" in dt:
            return "\U0001F4F7"
        if "tv" in dt:
            return "\U0001F4FA"
        if "printer" in dt:
            return "\U0001F5A8"
        if "linux" in dt or "server" in dt:
            return "\U0001F5C4"
        return "\U00002753"
