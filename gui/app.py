import customtkinter as ctk
import threading
import time
from typing import List, Dict
from modules.network_scanner import arp_scan, get_local_network_info
from modules.fingerprinter import fingerprint_device
from gui.widgets import DeviceCard


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("WiFi Device Scanner")
        self.geometry("900x700")
        self.minsize(700, 500)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.devices = []
        self.scanning = False
        self.network_info = get_local_network_info()

        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=15, pady=(10, 5))
        header.grid_columnconfigure(1, weight=1)

        title = ctk.CTkLabel(
            header,
            text="\U0001F6E1 WiFi Network Scanner",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w",
        )
        title.grid(row=0, column=0, sticky="w")

        self.info_label = ctk.CTkLabel(
            header,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=("#555555", "#AAAAAA"),
            anchor="w",
        )
        self.info_label.grid(row=0, column=1, sticky="w", padx=(10, 0))

        self.scan_btn = ctk.CTkButton(
            header,
            text="\U0001F50D Scan Network",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=36,
            width=160,
            corner_radius=8,
            command=self._start_scan,
        )
        self.scan_btn.grid(row=0, column=2, sticky="e")

        self.progress = ctk.CTkProgressBar(self)
        self.progress.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 0))
        self.progress.set(0)
        self.progress.grid_remove()

        main_frame = ctk.CTkFrame(self, corner_radius=10)
        main_frame.grid(row=2, column=0, sticky="nsew", padx=15, pady=(10, 15))
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)

        self.scroll_frame = ctk.CTkScrollableFrame(
            main_frame, corner_radius=8, fg_color=("gray95", "gray10")
        )
        self.scroll_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        self.status_bar = ctk.CTkFrame(self, height=30, corner_radius=0, fg_color=("gray90", "gray15"))
        self.status_bar.grid(row=3, column=0, sticky="ew")
        self.status_bar.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="Ready. Click 'Scan Network' to start.",
            font=ctk.CTkFont(size=11),
            text_color=("#666666", "#999999"),
            anchor="w",
        )
        self.status_label.grid(row=0, column=0, sticky="w", padx=10)

        self.count_label = ctk.CTkLabel(
            self.status_bar,
            text="Devices: 0",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="e",
        )
        self.count_label.grid(row=0, column=1, sticky="e", padx=10)

        self._update_network_info()

    def _update_network_info(self):
        if self.network_info:
            ip = self.network_info.get("local_ip", "?")
            network = self.network_info.get("network", "?")
            self.info_label.configure(text=f"Your IP: {ip}  |  Network: {network}")
        else:
            self.info_label.configure(text="Could not detect network")

    def _start_scan(self):
        if self.scanning:
            return

        self.scanning = True
        self.scan_btn.configure(state="disabled", text="\U000023F3 Scanning...")
        self.status_label.configure(text="Scanning network...")
        self.progress.grid()
        self.progress.set(0)

        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        self.devices = []

        thread = threading.Thread(target=self._scan_worker, daemon=True)
        thread.start()

    def _scan_worker(self):
        try:
            network = None
            if self.network_info:
                network = self.network_info.get("network")

            self.after(0, lambda: self.status_label.configure(text="Discovering devices via ARP scan..."))

            scan_results = arp_scan(network)

            total = len(scan_results) if scan_results else 0
            if total == 0:
                self.after(0, self._scan_complete)
                return

            self.after(0, lambda: self.status_label.configure(
                text=f"Found {total} devices. Fingerprinting each one..."
            ))

            gateway_ip = self.network_info.get("gateway") if self.network_info else None

            for i, device in enumerate(scan_results):
                if not self.scanning:
                    break

                progress = (i + 1) / total
                self.after(0, lambda p=progress: self.progress.set(p))

                self.after(0, lambda d=device: self.status_label.configure(
                    text=f"Fingerprinting {d.get('ip', '?')} ({i+1}/{total})..."
                ))

                result = fingerprint_device(
                    device.get("ip"),
                    device.get("mac"),
                    gateway_ip,
                )
                self.devices.append(result)

                self.after(0, lambda r=result: self._add_device_card(r))

        except Exception as e:
            self.after(0, lambda: self.status_label.configure(text=f"Error: {str(e)}"))
        finally:
            self.after(0, self._scan_complete)

    def _add_device_card(self, device_info: Dict):
        card = DeviceCard(self.scroll_frame, device_info)
        card.pack(fill="x", padx=5, pady=4)

    def _scan_complete(self):
        self.scanning = False
        self.scan_btn.configure(state="normal", text="\U0001F50D Scan Network")
        self.progress.grid_remove()

        count = len(self.devices)
        self.count_label.configure(text=f"Devices: {count}")

        if count == 0:
            self.status_label.configure(
                text="No devices found. Try running as Administrator."
            )
            no_devices = ctk.CTkLabel(
                self.scroll_frame,
                text="No devices detected.\nTry running this application as Administrator\nor check your WiFi connection.",
                font=ctk.CTkFont(size=14),
                text_color=("#888888", "#666666"),
                justify="center",
            )
            no_devices.pack(expand=True, fill="both", padx=50, pady=50)
        else:
            device_types = {}
            for d in self.devices:
                dt = d.get("device_type", "Unknown")
                device_types[dt] = device_types.get(dt, 0) + 1

            summary = ", ".join(f"{v}x {k}" for k, v in sorted(device_types.items()))
            self.status_label.configure(
                text=f"Scan complete! Found {count} devices. {summary}"
            )
