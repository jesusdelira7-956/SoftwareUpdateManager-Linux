#!/usr/bin/env python3
"""Linux / Zorin Software Update Manager & Intrusion Shield — Unified Entrypoint.

Dual-Mode Architecture (Option 2):
  --gui           Launch Zorin-themed Desktop GUI (Tkinter)
  --cli           Launch Interactive Terminal Menu (ANSI CLI)
  --check         Headless check for available updates (exit 0=clean, 100=updates)
  --upgrade-all   Headless sequential upgrade of all trusted updates (add --yes for cron)
  --audit-network Audit listening TCP ports for 0.0.0.0 LAN exposure
  --specs         Print hardware & mounted drive specifications
  --configure     Run Secondary Drive & Custom Directory Storage Wizard
  --snapshot      Create pre-update system snapshot (Timeshift / Snapper)
  --mcp           Start Zero-Port Stdio MCP Server (JSON-RPC over stdin/stdout)

100% Python Standard Library — Zero third-party pip dependencies.
"""

from __future__ import annotations

import argparse
import sys

from core.config_manager import APP_VERSION, load_config
from core.privilege_helper import (
    authenticate_sudo_upfront,
    ensure_tkinter_available,
    has_gui_display,
)
from core.rollback_manager import create_pre_update_snapshot
from ui.cli_app import (
    print_network_audit,
    print_system_specs,
    run_headless_check,
    run_headless_upgrade,
    run_interactive_cli,
    run_storage_wizard_cli,
)


def _try_launch_gui() -> int:
    """Attempt to launch the Tkinter GUI, offering auto-install of python3-tk with user consent."""
    if not has_gui_display():
        print("[Notice] No active X11/Wayland display detected. Falling back to Interactive CLI mode.\n")
        return run_interactive_cli(launch_gui_cb=None)

    if not ensure_tkinter_available(interactive=True):
        print("[Notice] Continuing in Interactive CLI mode...\n")
        return run_interactive_cli(launch_gui_cb=None)

    from ui.gui_app import launch_gui
    return launch_gui()


def _prompt_mode_choice() -> int:
    """Authenticate upfront (Linux least-privilege) and let the user choose GUI or CLI."""
    if not sys.stdin.isatty():
        return _try_launch_gui()

    if not authenticate_sudo_upfront(require_admin=True):
        return 1

    print(f"\nLinux / Zorin Software Update Manager (v{APP_VERSION})")
    print("Choose interface mode:")
    print("  [1] Desktop GUI (Tkinter — Visual Dashboard)")
    print("  [2] Interactive CLI (Terminal Menu)")
    choice = input("Select [1/2] (default 1): ").strip()
    if choice == "2":
        return run_interactive_cli(launch_gui_cb=_try_launch_gui)
    return _try_launch_gui()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="software-update-manager",
        description="Linux / Zorin Software Update Manager & Intrusion Shield (Dual-Mode CLI + GUI)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--gui", action="store_true", help="Launch Desktop GUI mode")
    mode_group.add_argument("--cli", action="store_true", help="Launch Interactive CLI mode")
    mode_group.add_argument("--check", action="store_true", help="Headless update check (exit 100 if updates exist)")
    mode_group.add_argument("--upgrade-all", action="store_true", help="Sequentially install all trusted updates")
    mode_group.add_argument("--audit-network", action="store_true", help="Audit listening TCP ports for LAN exposure")
    mode_group.add_argument("--specs", action="store_true", help="Display hardware and storage specifications")
    mode_group.add_argument("--configure", action="store_true", help="Run Secondary Drive & Storage Setup Wizard")
    mode_group.add_argument("--snapshot", action="store_true", help="Create pre-update Timeshift/Snapper snapshot")
    mode_group.add_argument("--mcp", action="store_true", help="Start Zero-Port Stdio MCP Server")

    parser.add_argument("--yes", "-y", action="store_true", help="Non-interactive confirmation for --upgrade-all")
    parser.add_argument("--with-snapshot", action="store_true", help="Create system snapshot before --upgrade-all")
    parser.add_argument("--json", action="store_true", help="Output JSON for --check or --specs")

    args = parser.parse_args(argv)

    if args.mcp:
        from agent_bridge import run_mcp_stdio_server
        return run_mcp_stdio_server()

    if args.check:
        return run_headless_check(as_json=args.json)

    if args.upgrade_all:
        if not authenticate_sudo_upfront(require_admin=True):
            return 1
        return run_headless_upgrade(auto_yes=args.yes, take_snapshot=args.with_snapshot)

    if args.audit_network:
        print_network_audit()
        return 0

    if args.specs:
        print_system_specs(as_json=args.json)
        return 0

    if args.configure:
        run_storage_wizard_cli(load_config())
        return 0

    if args.snapshot:
        if not authenticate_sudo_upfront(require_admin=True):
            return 1
        ok, msg = create_pre_update_snapshot(mode="cli", stream_cb=print)
        print(msg)
        return 0 if ok else 1

    if args.gui:
        if not authenticate_sudo_upfront(require_admin=True):
            return 1
        return _try_launch_gui()

    if args.cli:
        if not authenticate_sudo_upfront(require_admin=True):
            return 1
        return run_interactive_cli(launch_gui_cb=_try_launch_gui)

    # Default behavior when no explicit flag is passed
    cfg = load_config()
    pref = cfg.get("preferred_mode", "ask")
    if pref == "gui":
        if not authenticate_sudo_upfront(require_admin=True):
            return 1
        return _try_launch_gui()
    if pref == "cli":
        if not authenticate_sudo_upfront(require_admin=True):
            return 1
        return run_interactive_cli(launch_gui_cb=_try_launch_gui)
    return _prompt_mode_choice()


if __name__ == "__main__":
    raise SystemExit(main())
