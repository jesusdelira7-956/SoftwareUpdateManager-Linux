"""Interactive Terminal CLI & Headless Automation Runner for Linux.

100% Python Standard Library (zero third-party pip packages).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from core.config_manager import (
    APP_VERSION,
    CONFIG_FILE,
    detect_secondary_drives,
    load_config,
    save_config,
)
from core.network_auditor import audit_listening_ports, block_port_with_ufw, get_ufw_status
from core.package_engine import UpdateItem, refresh_apt_index
from core.privilege_helper import send_notification
from core.rollback_manager import create_pre_update_snapshot, detect_snapshot_tool
from core.scanner import apply_update_item, scan_all_updates
from core.specs_collector import collect_system_specs

# ANSI color codes
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"


def _banner() -> None:
    print(f"{CYAN}{'=' * 74}{NC}")
    print(f"{BOLD}  Linux / Zorin Software Update Manager & Intrusion Shield (v{APP_VERSION}){NC}")
    print(f"{DIM}  Zero Dependencies • Sequential Updates • Network Sentinel • Stdio MCP{NC}")
    print(f"{CYAN}{'=' * 74}{NC}\n")


def run_storage_wizard_cli(config: dict[str, Any]) -> dict[str, Any]:
    """Interactive CLI wizard asking if apps/SDKs live on secondary drives or custom paths."""
    print(f"\n{BOLD}--- Storage & Secondary Drive Configuration Wizard ---{NC}")
    print("By default, standard Linux paths (APT, Flatpak, Snap, ~/Applications) are scanned.")
    ans = input(
        "Do you have AppImages, AI engines, or portable apps installed on another drive or custom folder? [y/N]: "
    ).strip().lower()

    custom_dirs: list[str] = list(config.get("custom_app_dirs", []))
    if ans in ("y", "yes"):
        drives = detect_secondary_drives()
        if drives:
            print(f"\n{CYAN}Detected mounted non-root storage drives:{NC}")
            for idx, d in enumerate(drives, start=1):
                print(
                    f"  [{idx}] {d['mountpoint']} ({d['fstype']}, "
                    f"{d['free_gb']} GB free / {d['total_gb']} GB total)"
                )
            pick = input(
                "Enter drive numbers to include (comma-separated, e.g. 1,2) or press Enter to skip: "
            ).strip()
            for token in pick.split(","):
                token = token.strip()
                if token.isdigit():
                    i = int(token) - 1
                    if 0 <= i < len(drives):
                        mp = drives[i]["mountpoint"]
                        if mp not in custom_dirs:
                            custom_dirs.append(mp)
                            print(f"  {GREEN}+ Added drive path:{NC} {mp}")
        else:
            print(f"{DIM}No additional non-root mounted drives detected automatically.{NC}")

        while True:
            extra = input(
                "Add a custom directory path (e.g. /opt/apps or ~/PortableApps), or press Enter to finish: "
            ).strip()
            if not extra:
                break
            expanded = str(Path(os.path.expanduser(extra)))
            if Path(expanded).is_dir():
                if expanded not in custom_dirs:
                    custom_dirs.append(expanded)
                    print(f"  {GREEN}+ Added custom directory:{NC} {expanded}")
            else:
                print(f"  {YELLOW}Directory does not exist: {expanded}{NC}")

    config["custom_app_dirs"] = custom_dirs
    config["setup_completed"] = True
    save_config(config)
    print(f"{GREEN}Configuration saved to {CONFIG_FILE}{NC}\n")
    return config


def print_updates_table(items: list[UpdateItem]) -> None:
    if not items:
        print(f"{GREEN}All checked software packages, SDKs, and AppImages are up to date!{NC}\n")
        return

    print(f"\n{BOLD}{'#':<4} {'Source':<13} {'Package / App':<32} {'Current':<16} {'Available':<18} {'Trust'}{NC}")
    print("-" * 96)
    for idx, item in enumerate(items, start=1):
        color = GREEN if item.trust_status == "TRUSTED" else (YELLOW if item.trust_status == "WARNING" else RED)
        print(
            f"{idx:<4} {item.source:<13} {item.name[:31]:<32} "
            f"{item.current_version[:15]:<16} {item.available_version[:17]:<18} "
            f"{color}{item.trust_status}{NC}"
        )
    print("")


def print_network_audit() -> None:
    print(f"\n{BOLD}--- Linux Network Boundary Sentinel (Listening TCP Ports) ---{NC}")
    ufw_state = get_ufw_status()
    print(f"UFW Firewall Service Status: {CYAN}{ufw_state}{NC}\n")
    ports = audit_listening_ports()
    if not ports:
        print("No listening TCP ports detected.")
        return

    print(f"{BOLD}{'Port':<7} {'Bind Addr':<16} {'Process':<18} {'Service Hint':<30} {'Exposure'}{NC}")
    print("-" * 98)
    for p in ports:
        color = RED if p["exposure"] == "EXPOSED_LAN" else (GREEN if p["exposure"] == "ISOLATED" else YELLOW)
        print(
            f"{p['port']:<7} {p['bind_address'][:15]:<16} {p['process'][:17]:<18} "
            f"{p['service_hint'][:29]:<30} {color}{p['exposure_label']}{NC}"
        )
    print("")


def print_system_specs(as_json: bool = False) -> None:
    specs = collect_system_specs()
    if as_json:
        print(json.dumps(specs, indent=2))
        return
    print(f"\n{BOLD}--- System Hardware & Environment Specifications ---{NC}")
    print(f"  OS:              {specs['os_name']} (Kernel {specs['kernel']}, {specs['architecture']})")
    print(f"  Desktop Session: {specs['desktop_env']} ({specs['display_session']})")
    print(f"  CPU:             {specs['cpu']['model']} ({specs['cpu']['logical_cores']} threads)")
    print(
        f"  Memory:          {specs['memory']['used_gb']} GB used / "
        f"{specs['memory']['total_gb']} GB total"
    )
    print(f"  GPUs:            {', '.join(specs['gpus'])}")
    print(
        f"  Root Disk (/):   {specs['root_disk']['free_gb']} GB free / "
        f"{specs['root_disk']['total_gb']} GB total"
    )
    if specs["secondary_drives"]:
        print("  Other Drives:")
        for d in specs["secondary_drives"]:
            print(f"    - {d['mountpoint']} ({d['fstype']}): {d['free_gb']} GB free / {d['total_gb']} GB total")
    print("")


def run_headless_check(as_json: bool = False) -> int:
    """Non-interactive check mode. Exit 0 if up to date, 100 if updates available."""
    config = load_config()
    items = scan_all_updates(config)
    if as_json:
        print(json.dumps([i.to_dict() for i in items], indent=2))
    else:
        print_updates_table(items)
    return 100 if items else 0


def run_headless_upgrade(auto_yes: bool = False, take_snapshot: bool = False) -> int:
    """Sequential unattended or prompted upgrade of all trusted updates."""
    config = load_config()
    print(f"{CYAN}Refreshing APT package index...{NC}")
    refresh_apt_index(mode="cli", timeout_lock=int(config.get("apt_lock_timeout_seconds", 60)))

    items = scan_all_updates(config, progress_cb=lambda m: print(f"  {DIM}{m}{NC}"))
    print_updates_table(items)
    if not items:
        return 0

    trusted = [i for i in items if i.trust_status != "BLOCKED"]
    if not trusted:
        print(f"{RED}All available updates were blocked by the Security Trust Gate.{NC}")
        return 1

    if not auto_yes:
        ans = input(f"Proceed to sequentially update {len(trusted)} trusted item(s)? [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted by user.")
            return 0

    if take_snapshot or config.get("auto_snapshot_before_batch", False):
        ok, msg = create_pre_update_snapshot(mode="cli", stream_cb=print)
        print(f"{GREEN if ok else YELLOW}{msg}{NC}")

    failures = 0
    for idx, item in enumerate(trusted, start=1):
        print(f"\n{CYAN}[{idx}/{len(trusted)}] Updating {item.name} ({item.source})...{NC}")
        ok, msg = apply_update_item(item, mode="cli", config=config, stream_cb=lambda l: print(f"  {l}"))
        if ok:
            print(f"{GREEN}Updated {item.name} successfully.{NC}")
        else:
            failures += 1
            print(f"{RED}Failed to update {item.name}: {msg}{NC}")

    summary = f"Completed {len(trusted) - failures}/{len(trusted)} updates ({failures} failure(s))."
    print(f"\n{BOLD}{summary}{NC}")
    send_notification("Software Update Manager", summary, urgency="normal" if failures == 0 else "critical")
    return 0 if failures == 0 else 1


def run_interactive_cli(launch_gui_cb=None) -> int:
    """Interactive terminal menu giving full parity with the Desktop GUI."""
    _banner()
    config = load_config()
    if not config.get("setup_completed"):
        config = run_storage_wizard_cli(config)

    cached_items: list[UpdateItem] = []

    while True:
        print(f"{BOLD}Main Menu (Interactive CLI):{NC}")
        print("  [1] Scan for Available Updates (APT, Flatpak, Snap, Dev SDKs, AppImages)")
        print("  [2] Refresh APT Cache & Run Sequential Updates")
        print("  [3] Network Boundary Sentinel (Audit Exposed 0.0.0.0 AI/Dev Ports)")
        print("  [4] View Computer Specs & Mounted Drives")
        print("  [5] Create System Rollback Snapshot (Timeshift / Snapper)")
        print("  [6] Configure Secondary Drives & Custom App Folders")
        if launch_gui_cb:
            print("  [7] Switch to Desktop GUI Mode")
        print("  [8] Help & User Guide")
        print("  [0] Exit")

        choice = input("\nSelect an option: ").strip()
        if choice == "0":
            print("Goodbye.")
            return 0
        elif choice == "1":
            print(f"\n{CYAN}Scanning software sources in parallel...{NC}")
            cached_items = scan_all_updates(config, progress_cb=lambda m: print(f"  {DIM}{m}{NC}"))
            print_updates_table(cached_items)
        elif choice == "2":
            run_headless_upgrade(auto_yes=False)
        elif choice == "3":
            print_network_audit()
            port_in = input("Enter a port number to block external LAN access via UFW (or Enter to return): ").strip()
            if port_in.isdigit():
                ok, msg = block_port_with_ufw(int(port_in), mode="cli")
                print(f"{GREEN if ok else RED}{msg}{NC}\n")
        elif choice == "4":
            print_system_specs()
        elif choice == "5":
            tool = detect_snapshot_tool()
            print(f"Detected snapshot tool: {tool or 'None'}")
            ok, msg = create_pre_update_snapshot(mode="cli", stream_cb=print)
            print(f"{GREEN if ok else YELLOW}{msg}{NC}\n")
        elif choice == "6":
            config = run_storage_wizard_cli(config)
        elif choice == "7" and launch_gui_cb:
            return launch_gui_cb()
        elif choice == "8":
            print(f"\n{BOLD}--- Help & Quick Reference (v{APP_VERSION}) ---{NC}")
            print("  Flags: --gui | --cli | --check | --upgrade-all --yes | --audit-network | --specs | --configure | --snapshot | --mcp")
            print("  Config File: ~/.config/software-update-manager/config.json")
            print("  Audit Logs:  ~/.local/state/software-update-manager/logs/")
            print("  Security:    Runs unprivileged as $USER; elevates only APT/Snap/UFW/Timeshift via sudo/pkexec.")
            print("  Full Docs:   See README.md, AGENT_SAFETY.md, and SECURITY.md.\n")
        else:
            print(f"{YELLOW}Invalid option. Please choose from the menu.{NC}\n")
