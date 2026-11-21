"""Linux System Rollback Snapshot Manager (Timeshift / Snapper).

Provides the Linux equivalent of Windows System Restore Points before batch
system package upgrades.
"""

from __future__ import annotations

import shutil
from datetime import datetime
from typing import Callable

from core.privilege_helper import detect_system_package_manager, run_command


def detect_snapshot_tool() -> str | None:
    """Detect whether timeshift or snapper is installed on the host."""
    if shutil.which("timeshift"):
        return "timeshift"
    if shutil.which("snapper"):
        return "snapper"
    return None


def _snapshot_install_hint() -> str:
    pm = detect_system_package_manager()
    if pm == "dnf":
        return "sudo dnf install timeshift"
    if pm == "pacman":
        return "sudo pacman -S timeshift"
    if pm == "zypper":
        return "sudo zypper install snapper"
    return "sudo apt install timeshift"


def create_pre_update_snapshot(
    mode: str = "cli",
    comment: str | None = None,
    stream_cb: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """Create a system restore snapshot via Timeshift or Snapper."""
    tool = detect_snapshot_tool()
    if not tool:
        return (
            False,
            f"No system snapshot tool found. Install Timeshift/Snapper (`{_snapshot_install_hint()}`) "
            "to enable 1-click pre-update rollback points.",
        )

    tag = comment or f"SoftwareUpdateManager pre-update {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    if tool == "timeshift":
        cmd = ["timeshift", "--create", "--comments", tag, "--tags", "O"]
    else:
        cmd = ["snapper", "create", "--description", tag]

    rc, out = run_command(cmd, privileged=True, mode=mode, timeout=300, stream_cb=stream_cb)
    if rc == 0:
        return True, f"System snapshot created successfully via {tool}."
    return False, f"Snapshot creation via {tool} failed (exit {rc}): {out[-400:]}"
