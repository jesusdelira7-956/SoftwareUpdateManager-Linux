"""Zorin-Themed Desktop GUI for Linux Software Update Manager.

100% Python Standard Library (tkinter + ttk). Runs strictly as the regular
user ($USER); privileged operations invoke `pkexec` on demand.
"""

from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from core.ai_launcher import (
    WEB_AI_ASSISTANTS,
    detect_installed_local_ais,
    launch_local_ai,
    launch_web_ai,
)
from core.config_manager import (
    APP_VERSION,
    CONFIG_FILE,
    detect_secondary_drives,
    load_config,
    save_config,
)
from core.network_auditor import audit_listening_ports, block_port_with_ufw, get_ufw_status
from core.package_engine import UpdateItem, refresh_apt_index
from core.privilege_helper import copy_to_clipboard, send_notification
from core.rollback_manager import create_pre_update_snapshot, detect_snapshot_tool
from core.scanner import apply_update_item, scan_all_updates
from core.security_auditor import sanitize_for_ai
from core.specs_collector import collect_installed_apps, collect_system_specs

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"
PERMISSIONS_FILE = PROJECT_ROOT / "agent_permissions.json"

# Zorin OS Dark Palette
BG_DARK = "#181c24"
CARD_BG = "#212733"
ACCENT = "#15a6f0"
TEXT_PRIMARY = "#eef2f7"
TEXT_MUTED = "#9aa5b4"
SUCCESS = "#2ecc71"
WARNING = "#f1c40f"
DANGER = "#e74c3c"


class LinuxUpdateManagerGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Linux / Zorin Software Update Manager & Intrusion Shield (v{APP_VERSION})")
        self.geometry("1120x740")
        self.minsize(920, 620)
        self.configure(bg=BG_DARK)

        self.config_data: dict[str, Any] = load_config()
        self.updates: list[UpdateItem] = []
        self.is_busy = False

        # Hold references to PhotoImage objects so Tk never garbage-collects them
        self._app_icon: tk.PhotoImage | None = None
        self._bg_photo: tk.PhotoImage | None = None
        self._header_photo: tk.PhotoImage | None = None
        self._logo_photo: tk.PhotoImage | None = None

        self._load_visual_assets()
        self._configure_styles()
        self._build_background()
        self._build_header()
        self._build_tabs()

        if not self.config_data.get("setup_completed"):
            self.after(300, self._prompt_first_run_storage)

    def _load_visual_assets(self) -> None:
        """Load PNG banner and circular icon assets using 100% built-in tk.PhotoImage."""
        icon_path = ASSETS_DIR / "app_icon.png"
        if icon_path.is_file():
            try:
                self._app_icon = tk.PhotoImage(file=str(icon_path))
                self.iconphoto(True, self._app_icon)
            except tk.TclError:
                pass

        bg_path = ASSETS_DIR / "banner_bg.png"
        if bg_path.is_file():
            try:
                self._bg_photo = tk.PhotoImage(file=str(bg_path))
            except tk.TclError:
                pass

        header_path = ASSETS_DIR / "header_banner.png"
        if header_path.is_file():
            try:
                self._header_photo = tk.PhotoImage(file=str(header_path))
            except tk.TclError:
                pass

        logo_path = ASSETS_DIR / "logo_header.png"
        if logo_path.is_file():
            try:
                self._logo_photo = tk.PhotoImage(file=str(logo_path))
            except tk.TclError:
                pass

    def _build_background(self) -> None:
        """Render the darkened cyberpunk banner behind the entire root window."""
        if self._bg_photo is not None:
            bg_label = tk.Label(self, image=self._bg_photo, bg=BG_DARK, borderwidth=0)
            bg_label.place(x=0, y=0, relwidth=1.0, relheight=1.0)
            bg_label.lower()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=BG_DARK)
        style.configure("Card.TFrame", background=CARD_BG)
        style.configure("TLabel", background=BG_DARK, foreground=TEXT_PRIMARY, font=("Sans", 10))
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT_PRIMARY, font=("Sans", 10))
        style.configure("Title.TLabel", background=BG_DARK, foreground=TEXT_PRIMARY, font=("Sans", 14, "bold"))
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=CARD_BG,
            foreground=TEXT_MUTED,
            padding=(14, 8),
            font=("Sans", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT)],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Treeview",
            background=CARD_BG,
            foreground=TEXT_PRIMARY,
            fieldbackground=CARD_BG,
            rowheight=26,
            font=("Sans", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#2c3445",
            foreground=TEXT_PRIMARY,
            font=("Sans", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", "#294666")])

    def _build_header(self) -> None:
        self.header_canvas = tk.Canvas(
            self, height=84, bg=BG_DARK, highlightthickness=0, bd=0,
        )
        self.header_canvas.pack(fill=tk.X, padx=12, pady=(10, 6))

        if self._header_photo is not None:
            self.header_canvas.create_image(0, 0, anchor=tk.NW, image=self._header_photo)

        text_x = 18
        if self._logo_photo is not None:
            self.header_canvas.create_image(14, 42, anchor=tk.W, image=self._logo_photo)
            text_x = 86

        title_text = f"Linux / Zorin Software Update Manager  (v{APP_VERSION})"
        sub_text = "Sequential Verified Updates • Network Intrusion Shield • Zero-Port Stdio MCP"

        # Subtle drop shadow for maximum contrast over the cyberpunk banner
        self.header_canvas.create_text(
            text_x + 1, 29, anchor=tk.W, text=title_text,
            fill="#0a0d12", font=("Sans", 15, "bold"),
        )
        self.header_canvas.create_text(
            text_x, 28, anchor=tk.W, text=title_text,
            fill="#ffffff", font=("Sans", 15, "bold"),
        )
        self.header_canvas.create_text(
            text_x + 1, 56, anchor=tk.W, text=sub_text,
            fill="#0a0d12", font=("Sans", 9, "bold"),
        )
        self.header_canvas.create_text(
            text_x, 55, anchor=tk.W, text=sub_text,
            fill="#c7d5e8", font=("Sans", 9, "bold"),
        )

        # Right-aligned live status text (repositions automatically on window resize)
        self._status_shadow_id = self.header_canvas.create_text(
            1081, 43, anchor=tk.E, text="Ready",
            fill="#0a0d12", font=("Sans", 10, "bold"),
        )
        self._status_text_id = self.header_canvas.create_text(
            1080, 42, anchor=tk.E, text="Ready",
            fill="#56d4ff", font=("Sans", 10, "bold"),
        )

        def _on_header_resize(event: tk.Event) -> None:
            self.header_canvas.coords(self._status_shadow_id, event.width - 15, 43)
            self.header_canvas.coords(self._status_text_id, event.width - 16, 42)

        self.header_canvas.bind("<Configure>", _on_header_resize)

    def _build_tabs(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        self.tab_updater = ttk.Frame(self.notebook)
        self.tab_specs = ttk.Frame(self.notebook)
        self.tab_network = ttk.Frame(self.notebook)
        self.tab_ai = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        self.tab_help = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_updater, text="  Software Updater  ")
        self.notebook.add(self.tab_specs, text="  Specs & Installed Apps  ")
        self.notebook.add(self.tab_network, text="  Network Shield  ")
        self.notebook.add(self.tab_ai, text="  AI Diagnose & MCP  ")
        self.notebook.add(self.tab_settings, text="  Storage & Settings  ")
        self.notebook.add(self.tab_help, text="  Help & User Guide  ")

        self._build_updater_tab()
        self._build_specs_tab()
        self._build_network_tab()
        self._build_ai_tab()
        self._build_settings_tab()
        self._build_help_tab()

    # ------------------------------------------------------------------
    # Tab 1: Software Updater
    # ------------------------------------------------------------------
    def _build_updater_tab(self) -> None:
        toolbar = tk.Frame(self.tab_updater, bg=CARD_BG, padx=12, pady=10)
        toolbar.pack(fill=tk.X, padx=8, pady=8)

        tk.Button(
            toolbar, text="Scan All Sources", command=self._on_scan_updates,
            bg=ACCENT, fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            toolbar, text="Refresh APT Cache", command=self._on_refresh_apt,
            bg="#34495e", fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9),
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            toolbar, text="Update Selected", command=self._on_update_selected,
            bg="#27ae60", fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            toolbar, text="Update All Trusted", command=self._on_update_all,
            bg="#1e8449", fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 8))

        snap_tool = detect_snapshot_tool()
        snap_text = f"Create {snap_tool.title()} Snapshot" if snap_tool else "Snapshot (Install Timeshift)"
        tk.Button(
            toolbar, text=snap_text, command=self._on_create_snapshot,
            bg="#8e44ad", fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9),
        ).pack(side=tk.RIGHT)

        cols = ("source", "name", "current", "available", "trust")
        self.update_tree = ttk.Treeview(self.tab_updater, columns=cols, show="headings", selectmode="extended")
        self.update_tree.heading("source", text="Source")
        self.update_tree.heading("name", text="Package / Application")
        self.update_tree.heading("current", text="Current Version")
        self.update_tree.heading("available", text="Available Version")
        self.update_tree.heading("trust", text="Trust Gate")

        self.update_tree.column("source", width=120, anchor=tk.W)
        self.update_tree.column("name", width=340, anchor=tk.W)
        self.update_tree.column("current", width=170, anchor=tk.W)
        self.update_tree.column("available", width=190, anchor=tk.W)
        self.update_tree.column("trust", width=110, anchor=tk.CENTER)
        self.update_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        self.log_box = scrolledtext.ScrolledText(
            self.tab_updater, height=10, bg="#10131a", fg="#d8dee9",
            insertbackground="#ffffff", font=("Monospace", 9), relief=tk.FLAT,
        )
        self.log_box.pack(fill=tk.X, padx=8, pady=(0, 8))
        self._log("Ready. Click 'Scan All Sources' to check APT, Flatpak, Snap, Dev SDKs, and AppImages.")

    def _log(self, message: str) -> None:
        def _append() -> None:
            self.log_box.insert(tk.END, message + "\n")
            self.log_box.see(tk.END)
        self.after(0, _append)

    def _set_status(self, text: str) -> None:
        def _update() -> None:
            self.header_canvas.itemconfig(self._status_shadow_id, text=text)
            self.header_canvas.itemconfig(self._status_text_id, text=text)
        self.after(0, _update)

    def _on_scan_updates(self) -> None:
        if self.is_busy:
            return
        self.is_busy = True
        self._set_status("Scanning software sources...")
        self._log("\n--- Scanning all configured software sources ---")

        def _worker() -> None:
            try:
                found = scan_all_updates(self.config_data, progress_cb=self._log)
                self.updates = found

                def _populate() -> None:
                    for row in self.update_tree.get_children():
                        self.update_tree.delete(row)
                    for idx, item in enumerate(found):
                        self.update_tree.insert(
                            "", tk.END, iid=str(idx),
                            values=(item.source, item.name, item.current_version, item.available_version, item.trust_status),
                        )
                    self._set_status(f"Scan complete: {len(found)} update(s) found")
                    self._log(f"Scan finished: {len(found)} update(s) available.")
                self.after(0, _populate)
            finally:
                self.is_busy = False

        threading.Thread(target=_worker, daemon=True).start()

    def _on_refresh_apt(self) -> None:
        if self.is_busy:
            return
        self.is_busy = True
        self._set_status("Refreshing APT index...")
        self._log("\n--- Refreshing APT repository index (pkexec) ---")

        def _worker() -> None:
            try:
                ok, out = refresh_apt_index(mode="gui", stream_cb=self._log)
                self._set_status("APT index refreshed" if ok else "APT refresh warning")
                if not ok:
                    self._log(f"APT refresh issue: {out[-300:]}")
            finally:
                self.is_busy = False
                self.after(400, self._on_scan_updates)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_create_snapshot(self) -> None:
        if self.is_busy:
            return
        self.is_busy = True
        self._set_status("Creating system snapshot...")
        self._log("\n--- Creating pre-update system snapshot ---")

        def _worker() -> None:
            try:
                ok, msg = create_pre_update_snapshot(mode="gui", stream_cb=self._log)
                self._log(msg)
                self._set_status("Snapshot created" if ok else "Snapshot unavailable")
            finally:
                self.is_busy = False

        threading.Thread(target=_worker, daemon=True).start()

    def _run_update_batch(self, batch: list[UpdateItem]) -> None:
        if not batch or self.is_busy:
            return
        self.is_busy = True
        self._set_status(f"Updating {len(batch)} item(s)...")

        def _worker() -> None:
            failures = 0
            try:
                for idx, item in enumerate(batch, start=1):
                    self._log(f"\n[{idx}/{len(batch)}] Updating {item.name} ({item.source})...")
                    ok, msg = apply_update_item(item, mode="gui", config=self.config_data, stream_cb=self._log)
                    if ok:
                        self._log(f"SUCCESS: {item.name}")
                    else:
                        failures += 1
                        self._log(f"FAILED: {item.name} -> {msg}")
                summary = f"Finished {len(batch) - failures}/{len(batch)} updates ({failures} failure(s))."
                self._log(f"\n=== {summary} ===")
                self._set_status(summary)
                send_notification("Software Update Manager", summary)
            finally:
                self.is_busy = False
                self.after(400, self._on_scan_updates)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_update_selected(self) -> None:
        sel = self.update_tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Please select one or more rows to update.")
            return
        batch = [self.updates[int(iid)] for iid in sel if self.updates[int(iid)].trust_status != "BLOCKED"]
        self._run_update_batch(batch)

    def _on_update_all(self) -> None:
        trusted = [u for u in self.updates if u.trust_status != "BLOCKED"]
        if not trusted:
            messagebox.showinfo("Up to Date", "No trusted updates are currently pending. Run a scan first.")
            return
        if messagebox.askyesno("Confirm Batch Update", f"Sequentially update {len(trusted)} trusted item(s)?"):
            self._run_update_batch(trusted)

    # ------------------------------------------------------------------
    # Tab 2: Specs & Installed Apps
    # ------------------------------------------------------------------
    def _build_specs_tab(self) -> None:
        top = tk.Frame(self.tab_specs, bg=CARD_BG, padx=14, pady=12)
        top.pack(fill=tk.X, padx=8, pady=8)

        self.specs_text = tk.Label(
            top, text="Click 'Refresh Specs & Inventory' to inspect hardware.",
            bg=CARD_BG, fg=TEXT_PRIMARY, justify=tk.LEFT, font=("Monospace", 9),
        )
        self.specs_text.pack(side=tk.LEFT, anchor=tk.W)

        tk.Button(
            top, text="Refresh Specs & Inventory", command=self._on_load_specs,
            bg=ACCENT, fg="#ffffff", relief=tk.FLAT, padx=12, pady=6,
        ).pack(side=tk.RIGHT, anchor=tk.N)

        cols = ("source", "name", "id", "version")
        self.inv_tree = ttk.Treeview(self.tab_specs, columns=cols, show="headings")
        for col, title, w in (
            ("source", "Source", 120),
            ("name", "Application / Package", 280),
            ("id", "Identifier", 280),
            ("version", "Version", 180),
        ):
            self.inv_tree.heading(col, text=title)
            self.inv_tree.column(col, width=w, anchor=tk.W)
        self.inv_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

    def _on_load_specs(self) -> None:
        def _worker() -> None:
            specs = collect_system_specs()
            apps = collect_installed_apps()
            summary = (
                f"OS:      {specs['os_name']} (Kernel {specs['kernel']}, {specs['architecture']})\n"
                f"Session: {specs['desktop_env']} ({specs['display_session']}) | Python {specs['python_version']}\n"
                f"CPU:     {specs['cpu']['model']} ({specs['cpu']['logical_cores']} threads)\n"
                f"RAM:     {specs['memory']['used_gb']} / {specs['memory']['total_gb']} GB\n"
                f"GPU:     {', '.join(specs['gpus'])}\n"
                f"Root /:  {specs['root_disk']['free_gb']} GB free / {specs['root_disk']['total_gb']} GB total"
            )

            def _update_ui() -> None:
                self.specs_text.config(text=summary)
                for r in self.inv_tree.get_children():
                    self.inv_tree.delete(r)
                for app in apps:
                    self.inv_tree.insert("", tk.END, values=(app["source"], app["name"], app["id"], app["version"]))
            self.after(0, _update_ui)

        threading.Thread(target=_worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Tab 3: Network Boundary Sentinel
    # ------------------------------------------------------------------
    def _build_network_tab(self) -> None:
        bar = tk.Frame(self.tab_network, bg=CARD_BG, padx=12, pady=10)
        bar.pack(fill=tk.X, padx=8, pady=8)

        tk.Button(
            bar, text="Audit Listening TCP Ports", command=self._on_audit_network,
            bg=ACCENT, fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            bar, text="Block Selected Port via UFW", command=self._on_block_port,
            bg=DANGER, fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9, "bold"),
        ).pack(side=tk.LEFT)

        self.ufw_label = tk.Label(bar, text=f"UFW Status: {get_ufw_status()}", bg=CARD_BG, fg=TEXT_MUTED)
        self.ufw_label.pack(side=tk.RIGHT)

        cols = ("port", "bind", "process", "hint", "exposure")
        self.net_tree = ttk.Treeview(self.tab_network, columns=cols, show="headings")
        for col, title, w in (
            ("port", "Port", 80),
            ("bind", "Bind Address", 150),
            ("process", "Process", 180),
            ("hint", "Service / AI Engine", 260),
            ("exposure", "Exposure Status", 240),
        ):
            self.net_tree.heading(col, text=title)
            self.net_tree.column(col, width=w, anchor=tk.W)
        self.net_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

    def _on_audit_network(self) -> None:
        ports = audit_listening_ports()
        self.ufw_label.config(text=f"UFW Status: {get_ufw_status()}")
        for r in self.net_tree.get_children():
            self.net_tree.delete(r)
        for p in ports:
            self.net_tree.insert(
                "", tk.END,
                values=(p["port"], p["bind_address"], p["process"], p["service_hint"], p["exposure_label"]),
            )

    def _on_block_port(self) -> None:
        sel = self.net_tree.selection()
        if not sel:
            messagebox.showinfo("Select Port", "Select a listening port row to block external LAN access via UFW.")
            return
        port = int(self.net_tree.item(sel[0])["values"][0])
        if messagebox.askyesno("UFW Firewall Rule", f"Block external inbound TCP traffic on port {port} via UFW?"):
            ok, msg = block_port_with_ufw(port, mode="gui")
            messagebox.showinfo("UFW Result", msg) if ok else messagebox.showerror("UFW Error", msg)

    # ------------------------------------------------------------------
    # Tab 4: AI Diagnose & Zero-Port Stdio MCP Bridge
    # ------------------------------------------------------------------
    def _build_ai_tab(self) -> None:
        card = tk.Frame(self.tab_ai, bg=CARD_BG, padx=16, pady=12)
        card.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        tk.Label(
            card,
            text="Zero-Port Stdio MCP Server & AI Diagnostic Launchpad",
            bg=CARD_BG, fg=TEXT_PRIMARY, font=("Sans", 12, "bold"),
        ).pack(anchor=tk.W, pady=(0, 4))

        tk.Label(
            card,
            text="Copy a sanitized system diagnostic bundle to paste into any Web AI, or launch your locally installed AI clients.",
            bg=CARD_BG, fg=TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(0, 10))

        self._mcp_snippet = json.dumps(
            {
                "mcpServers": {
                    "linux-software-update-manager": {
                        "command": "python3",
                        "args": [str(PROJECT_ROOT / "update_manager.py"), "--mcp"],
                    }
                }
            },
            indent=2,
        )

        # Primary Actions Row
        action_row = tk.Frame(card, bg=CARD_BG)
        action_row.pack(fill=tk.X, pady=(0, 12))

        tk.Button(
            action_row, text="Copy AI Diagnostic Bundle",
            command=self._on_copy_ai_bundle,
            bg=ACCENT, fg="#ffffff", relief=tk.FLAT, padx=14, pady=7, font=("Sans", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            action_row, text="Copy MCP Config JSON",
            command=self._on_copy_mcp_json,
            bg="#34495e", fg="#ffffff", relief=tk.FLAT, padx=14, pady=7, font=("Sans", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            action_row, text="Refresh Local AIs",
            command=self._refresh_local_ai_buttons,
            bg="#2c3445", fg=TEXT_PRIMARY, relief=tk.FLAT, padx=12, pady=7, font=("Sans", 9),
        ).pack(side=tk.RIGHT)

        # Option A: Web AI Links
        tk.Label(
            card, text="Web AI Assistants (Opens in Default Browser):",
            bg=CARD_BG, fg=TEXT_PRIMARY, font=("Sans", 10, "bold"),
        ).pack(anchor=tk.W, pady=(2, 6))

        web_row = tk.Frame(card, bg=CARD_BG)
        web_row.pack(fill=tk.X, pady=(0, 12))
        for ai in WEB_AI_ASSISTANTS:
            url = ai["url"]
            tk.Button(
                web_row,
                text=f"🌐 {ai['name']}",
                command=lambda u=url, n=ai["name"]: self._on_launch_web_ai(u, n),
                bg=ai["color"], fg="#ffffff", relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9, "bold"),
            ).pack(side=tk.LEFT, padx=(0, 8))

        # Option B: Dynamically Detected Local Installed AI Shortcuts
        tk.Label(
            card, text="Installed Local AI Apps & IDEs (Auto-Detected on This Machine):",
            bg=CARD_BG, fg=TEXT_PRIMARY, font=("Sans", 10, "bold"),
        ).pack(anchor=tk.W, pady=(2, 6))

        self.local_ai_frame = tk.Frame(card, bg="#181d27", padx=10, pady=10)
        self.local_ai_frame.pack(fill=tk.X, pady=(0, 12))
        self._refresh_local_ai_buttons()

        # MCP Config Snippet
        tk.Label(
            card, text="Zero-Port Stdio MCP Client Configuration Snippet:",
            bg=CARD_BG, fg=TEXT_PRIMARY, font=("Sans", 10, "bold"),
        ).pack(anchor=tk.W)
        box = scrolledtext.ScrolledText(card, height=8, bg="#10131a", fg="#a3be8c", font=("Monospace", 9), relief=tk.FLAT)
        box.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        box.insert("1.0", self._mcp_snippet)
        box.config(state=tk.DISABLED)

    def _on_launch_web_ai(self, url: str, name: str) -> None:
        ok, msg = launch_web_ai(url)
        if ok:
            self._set_status(f"Opened {name} in browser")
        else:
            messagebox.showerror("Browser Error", msg)

    def _on_launch_local_ai(self, app: dict[str, str]) -> None:
        ok, msg = launch_local_ai(app)
        if ok:
            self._set_status(msg)
        else:
            messagebox.showerror("Launch Error", msg)

    def _refresh_local_ai_buttons(self) -> None:
        for widget in self.local_ai_frame.winfo_children():
            widget.destroy()

        detected = detect_installed_local_ais()
        if not detected:
            tk.Label(
                self.local_ai_frame,
                text="No local AI desktop apps detected yet. Install Antigravity, Claude Desktop, LM Studio, Ollama, or Cursor and click 'Refresh Local AIs'.",
                bg="#181d27", fg=TEXT_MUTED, font=("Sans", 9),
            ).pack(anchor=tk.W)
            return

        cols_per_row = 4
        for idx, app in enumerate(detected):
            row_i = idx // cols_per_row
            col_i = idx % cols_per_row
            tk.Button(
                self.local_ai_frame,
                text=f"🚀 {app['label']}",
                command=lambda a=app: self._on_launch_local_ai(a),
                bg="#28354a", fg="#eef2f7", activebackground=ACCENT, activeforeground="#ffffff",
                relief=tk.FLAT, padx=12, pady=6, font=("Sans", 9, "bold"), width=18,
            ).grid(row=row_i, column=col_i, padx=6, pady=4, sticky="w")

    def _on_copy_mcp_json(self) -> None:
        ok, msg = copy_to_clipboard(self._mcp_snippet)
        if not ok:
            self.clipboard_clear()
            self.clipboard_append(self._mcp_snippet)
            msg = "Copied MCP JSON via Tkinter clipboard."
        messagebox.showinfo("MCP Config Copied", msg)

    def _on_copy_ai_bundle(self) -> None:
        specs = collect_system_specs()
        ports = audit_listening_ports()
        exposed = [p for p in ports if p["exposure"] == "EXPOSED_LAN"]
        bundle = (
            "=== LINUX SOFTWARE UPDATE MANAGER — SANITIZED DIAGNOSTIC BUNDLE ===\n"
            f"OS: {specs['os_name']} | Kernel: {specs['kernel']} | Session: {specs['display_session']}\n"
            f"CPU: {specs['cpu']['model']} | RAM: {specs['memory']['total_gb']} GB | GPUs: {', '.join(specs['gpus'])}\n"
            f"Pending Updates Cached: {len(self.updates)}\n"
            f"Exposed LAN (0.0.0.0) Ports: {len(exposed)}\n"
            + "\n".join(f"  - Port {p['port']} ({p['process']}): {p['service_hint']}" for p in exposed)
        )
        clean = sanitize_for_ai(bundle)
        ok, msg = copy_to_clipboard(clean)
        if not ok:
            self.clipboard_clear()
            self.clipboard_append(clean)
            msg = "Copied via Tkinter clipboard."
        messagebox.showinfo("AI Diagnostic Bundle", msg)

    # ------------------------------------------------------------------
    # Tab 5: Storage & Secondary Drives
    # ------------------------------------------------------------------
    def _build_settings_tab(self) -> None:
        card = tk.Frame(self.tab_settings, bg=CARD_BG, padx=16, pady=14)
        card.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        tk.Label(
            card,
            text="Secondary Drives & Custom Application Directories",
            bg=CARD_BG, fg=TEXT_PRIMARY, font=("Sans", 12, "bold"),
        ).pack(anchor=tk.W, pady=(0, 6))

        tk.Label(
            card,
            text="Configure additional drives or folders where you store AppImages, portable AI tools, or SDKs.",
            bg=CARD_BG, fg=TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(0, 10))

        self.dirs_listbox = tk.Listbox(card, height=8, bg="#10131a", fg=TEXT_PRIMARY, font=("Monospace", 10), relief=tk.FLAT)
        self.dirs_listbox.pack(fill=tk.X, pady=(0, 10))
        self._refresh_dirs_listbox()

        btns = tk.Frame(card, bg=CARD_BG)
        btns.pack(fill=tk.X)

        tk.Button(btns, text="Auto-Detect Mounted Drives", command=self._on_autodetect_drives, bg=ACCENT, fg="#ffffff", relief=tk.FLAT, padx=10, pady=6).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(btns, text="Browse Custom Folder...", command=self._on_browse_folder, bg="#34495e", fg="#ffffff", relief=tk.FLAT, padx=10, pady=6).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(btns, text="Remove Selected", command=self._on_remove_dir, bg=DANGER, fg="#ffffff", relief=tk.FLAT, padx=10, pady=6).pack(side=tk.LEFT)

        tk.Label(card, text=f"Config File: {CONFIG_FILE}", bg=CARD_BG, fg=TEXT_MUTED, font=("Monospace", 8)).pack(anchor=tk.W, pady=(14, 0))

    def _refresh_dirs_listbox(self) -> None:
        self.dirs_listbox.delete(0, tk.END)
        for d in self.config_data.get("custom_app_dirs", []):
            self.dirs_listbox.insert(tk.END, d)

    def _on_autodetect_drives(self) -> None:
        drives = detect_secondary_drives()
        if not drives:
            messagebox.showinfo("No Secondary Drives", "No additional non-root mounted drives were detected.")
            return
        added = 0
        dirs = list(self.config_data.get("custom_app_dirs", []))
        for d in drives:
            mp = d["mountpoint"]
            if mp not in dirs:
                if messagebox.askyesno(
                    "Secondary Drive Detected",
                    f"Add mounted drive to standalone software scan?\n\n{mp} ({d['fstype']}, {d['free_gb']} GB free)",
                ):
                    dirs.append(mp)
                    added += 1
        self.config_data["custom_app_dirs"] = dirs
        self.config_data["setup_completed"] = True
        save_config(self.config_data)
        self._refresh_dirs_listbox()
        if added:
            self._log(f"Added {added} secondary drive path(s) to scan configuration.")

    def _on_browse_folder(self) -> None:
        folder = filedialog.askdirectory(title="Select Custom Applications or Secondary Drive Folder")
        if folder:
            dirs = list(self.config_data.get("custom_app_dirs", []))
            if folder not in dirs:
                dirs.append(folder)
                self.config_data["custom_app_dirs"] = dirs
                self.config_data["setup_completed"] = True
                save_config(self.config_data)
                self._refresh_dirs_listbox()

    def _on_remove_dir(self) -> None:
        sel = self.dirs_listbox.curselection()
        if not sel:
            return
        dirs = list(self.config_data.get("custom_app_dirs", []))
        dirs.pop(sel[0])
        self.config_data["custom_app_dirs"] = dirs
        save_config(self.config_data)
        self._refresh_dirs_listbox()

    def _prompt_first_run_storage(self) -> None:
        ans = messagebox.askyesno(
            "First-Run Storage Setup",
            "Do you store AppImages, portable tools, or AI apps on a secondary drive or custom folder?\n\n"
            "(Click Yes to auto-detect mounted drives or choose a folder, or No to scan standard Linux paths only.)",
        )
        self.config_data["setup_completed"] = True
        save_config(self.config_data)
        if ans:
            self.notebook.select(self.tab_settings)
            self._on_autodetect_drives()


    # ------------------------------------------------------------------
    # Tab 6: Help & User Guide
    # ------------------------------------------------------------------
    def _build_help_tab(self) -> None:
        help_frame = tk.Frame(self.tab_help, bg=CARD_BG, padx=16, pady=12)
        help_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Brand Hero Card
        brand_card = tk.Frame(
            help_frame, bg="#131c2e",
            highlightbackground="#0284c7", highlightthickness=1, padx=14, pady=10,
        )
        brand_card.pack(fill=tk.X, pady=(0, 10))

        if self._logo_photo is not None:
            tk.Label(brand_card, image=self._logo_photo, bg="#131c2e").pack(side=tk.LEFT, padx=(4, 14))

        brand_info = tk.Frame(brand_card, bg="#131c2e")
        brand_info.pack(side=tk.LEFT, fill=tk.Y)

        tk.Label(
            brand_info,
            text="Linux / Zorin Software Update Manager & Intrusion Shield",
            bg="#131c2e", fg="#38bdf8", font=("Sans", 12, "bold"),
        ).pack(anchor=tk.W)
        tk.Label(
            brand_info,
            text="Dual-Mode (GUI + CLI) • 100% Python Standard Library (Zero pip Dependencies) • MIT Open-Source",
            bg="#131c2e", fg="#cbd5e1", font=("Sans", 9),
        ).pack(anchor=tk.W, pady=(2, 0))
        tk.Label(
            brand_info,
            text="Support future open-source development: https://buymeacoffee.com/JesseInTheLab",
            bg="#131c2e", fg="#94a3b8", font=("Sans", 9),
        ).pack(anchor=tk.W, pady=(2, 0))

        tk.Button(
            brand_card,
            text="☕ Buy Me A Coffee",
            command=lambda: launch_web_ai("https://buymeacoffee.com/JesseInTheLab"),
            bg="#f59e0b", fg="#000000", activebackground="#d97706", activeforeground="#ffffff",
            font=("Sans", 9, "bold"), relief=tk.FLAT, padx=14, pady=7, cursor="hand2",
        ).pack(side=tk.RIGHT, padx=6)

        help_text = scrolledtext.ScrolledText(
            help_frame, bg="#10131a", fg=TEXT_PRIMARY, font=("Sans", 10),
            relief=tk.FLAT, wrap=tk.WORD, padx=14, pady=10,
        )
        help_text.pack(fill=tk.BOTH, expand=True)

        guide_content = f"""📘 WELCOME TO LINUX / ZORIN SOFTWARE UPDATE MANAGER & INTRUSION SHIELD (v{APP_VERSION})
================================================================================
Keep your Linux desktop (Zorin OS, Ubuntu, Linux Mint, Pop!_OS, Debian) fully
updated while proactively protecting it from exposed local AI ports (0.0.0.0)
and untrusted packages — 100% Free, Transparent, and Zero pip Dependencies.

--------------------------------------------------------------------------------
1. DUAL-MODE USAGE (CHOOSE GUI, CLI, HEADLESS, OR MCP)
--------------------------------------------------------------------------------
You can run this tool in whichever mode fits your workflow:
  • Desktop GUI Mode:     software-update-manager --gui   (or Desktop icon)
  • Interactive CLI Mode: software-update-manager --cli
  • Headless Check:       software-update-manager --check (exit 100 if updates exist)
  • Unattended Upgrade:   software-update-manager --upgrade-all --yes --with-snapshot
  • Storage Setup Wizard: software-update-manager --configure
  • Zero-Port MCP Bridge: software-update-manager --mcp

Note on Tkinter: If `python3-tk` is missing on a fresh Linux install, the app
will ask your permission to install it automatically or fall back cleanly to CLI.

--------------------------------------------------------------------------------
2. HYBRID SCANNING & SMART BANDWIDTH CACHING
--------------------------------------------------------------------------------
Click "Scan All Sources" to audit all enabled update channels in parallel:
  • System Packages: APT (with background dpkg lock-waiter), Flatpak, and Snap.
  • Developer SDKs:  rustup, uv, bun, pnpm, and flutter — verified against live
                     upstream semver releases so up-to-date tools never trigger
                     phantom updates.
  • Standalone Apps & AppImages (providers.json):
                     Obsidian, Joplin, LM Studio, AnythingLLM, Telegram Desktop,
                     balenaEtcher, and Docker Desktop (dynamic release-notes
                     build-ID scraper). Uses ETag, HTTP Redirect, Release Tag,
                     and Build-ID caching to skip gigabytes of redundant downloads.

--------------------------------------------------------------------------------
3. SECONDARY DRIVES & CUSTOM APPLICATION FOLDERS
--------------------------------------------------------------------------------
Unlike hardcoded scripts, this updater dynamically inspects `/proc/mounts` to
discover external or secondary storage drives (`/media/...`, `/mnt/...`).
  • Open the "Storage & Settings" tab (or run `--configure` in CLI) to add
    secondary drives or custom folders where you keep AppImages or portable tools.
  • Settings are stored in `~/.config/software-update-manager/config.json`.

--------------------------------------------------------------------------------
4. LEAST-PRIVILEGE SECURITY, TRUST GATE & SYSTEM ROLLBACK
--------------------------------------------------------------------------------
  • Linux Least-Privilege Rule: The GUI never runs as root (protecting Wayland,
    desktop themes, Flatpak user installs, and ~/.config ownership). Only system
    package actions elevate via `pkexec` (GUI) or `sudo` (CLI).
  • Pre-Update Trust Gate: Screens packages against `pup_blocklist.json`, flags
    high-risk paths (`/tmp`, `/dev/shm`), and verifies SHA-256 checksums.
  • 1-Click Rollback Snapshot: Auto-detects Timeshift or Snapper so you can
    create a system restore snapshot before applying batch OS updates.

--------------------------------------------------------------------------------
5. NETWORK BOUNDARY SENTINEL & UFW FIREWALL HARDENER
--------------------------------------------------------------------------------
Open the "Network Shield" tab and click "Audit Listening TCP Ports" to scan
local AI & developer endpoints (Ollama 11434, LM Studio 1234, Open WebUI 8081,
ComfyUI 8188, SwarmUI 7801, dev ports 3000-5000, 8000-9000):
  • Localhost (Isolated): Bound safely to 127.0.0.1 / ::1.
  • EXPOSED TO LAN (0.0.0.0 / ::): Reachable from other devices on Wi-Fi/LAN.
  • Select any exposed port and click "Block Selected Port via UFW" to add a
    native UFW inbound deny rule while keeping localhost access working.

--------------------------------------------------------------------------------
6. AI DIAGNOSE, LOCAL SHORTCUTS & ZERO-PORT STDIO MCP BRIDGE
--------------------------------------------------------------------------------
Inside the "AI Diagnose & MCP" tab:
  • Click "Copy AI Diagnostic Bundle" to copy a sanitized hardware/network/update
    summary, then click any Web AI button (Gemini, Claude, ChatGPT, Copilot,
    Perplexity) or any auto-detected Local AI shortcut to launch and paste.
  • Zero-Port Stdio MCP: Copy the MCP JSON snippet into Antigravity IDE, Claude
    Desktop, or Cursor. It communicates strictly over stdin/stdout with ZERO
    open TCP ports and Indirect Prompt Injection (IPI) output sanitization.
  • Safety Guide: Read `AGENT_SAFETY.md` and `SECURITY.md` in the repository.

🎥 Recommended MCP & AI Security Resources:
  • Official MCP Security Best Practices:
    https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices
  • Securing the MCP Server (Overview):
    https://www.youtube.com/watch?v=KYWr454hGF0
  • Least Privilege for AI Agents:
    https://www.youtube.com/watch?v=4HiuiYIJRTU
"""
        help_text.insert("1.0", guide_content)
        help_text.config(state=tk.DISABLED)


def launch_gui() -> int:
    app = LinuxUpdateManagerGUI()
    app.mainloop()
    return 0
