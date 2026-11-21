"""Linux hardware specifications and installed software inventory collector.

100% Python Standard Library. Works on Zorin OS, Ubuntu, Debian, Linux Mint,
and Pop!_OS.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.config_manager import detect_secondary_drives
from core.privilege_helper import get_session_type


def _read_os_release() -> dict[str, str]:
    info: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return info
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return info


def _get_cpu_info() -> dict[str, Any]:
    model = platform.processor() or "Unknown CPU"
    cores = os.cpu_count() or 1
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        try:
            for line in cpuinfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.lower().startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    return {"model": model, "logical_cores": cores}


def _get_memory_info() -> dict[str, float]:
    total_kb = 0
    avail_kb = 0
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        try:
            for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("MemTotal:"):
                    total_kb = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail_kb = int(line.split()[1])
        except (OSError, ValueError):
            pass
    total_gb = round(total_kb / (1024 ** 2), 2)
    avail_gb = round(avail_kb / (1024 ** 2), 2)
    used_gb = round(max(0.0, total_gb - avail_gb), 2)
    return {"total_gb": total_gb, "used_gb": used_gb, "available_gb": avail_gb}


def _get_gpu_info() -> list[str]:
    gpus: list[str] = []
    lspci = shutil.which("lspci")
    if lspci:
        try:
            res = subprocess.run(
                [lspci],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in res.stdout.splitlines():
                lower = line.lower()
                if "vga compatible controller" in lower or "3d controller" in lower or "display controller" in lower:
                    parts = line.split(":", 2)
                    if len(parts) >= 3:
                        gpus.append(parts[2].strip())
        except (OSError, subprocess.SubprocessError):
            pass
    return gpus or ["Unknown GPU"]


def collect_system_specs() -> dict[str, Any]:
    """Collect a comprehensive, privacy-safe hardware & OS snapshot."""
    os_rel = _read_os_release()
    root_usage = shutil.disk_usage("/")
    secondary = detect_secondary_drives()

    return {
        "os_name": os_rel.get("PRETTY_NAME", platform.system()),
        "os_id": os_rel.get("ID", "linux"),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "desktop_env": os.environ.get("XDG_CURRENT_DESKTOP", "Unknown"),
        "display_session": get_session_type(),
        "python_version": platform.python_version(),
        "cpu": _get_cpu_info(),
        "memory": _get_memory_info(),
        "gpus": _get_gpu_info(),
        "root_disk": {
            "mountpoint": "/",
            "total_gb": round(root_usage.total / (1024 ** 3), 1),
            "free_gb": round(root_usage.free / (1024 ** 3), 1),
        },
        "secondary_drives": secondary,
    }


def collect_installed_apps(limit: int = 300) -> list[dict[str, str]]:
    """Collect installed software inventory across Flatpak, Snap, and APT."""
    apps: list[dict[str, str]] = []

    # 1. Flatpak apps
    if shutil.which("flatpak"):
        try:
            res = subprocess.run(
                ["flatpak", "list", "--app", "--columns=name,application,version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in res.stdout.splitlines():
                cols = line.split("\t")
                if len(cols) >= 2:
                    apps.append({
                        "name": cols[0].strip(),
                        "id": cols[1].strip(),
                        "version": cols[2].strip() if len(cols) > 2 else "",
                        "source": "Flatpak",
                    })
        except (OSError, subprocess.SubprocessError):
            pass

    # 2. Snap packages
    if shutil.which("snap"):
        try:
            res = subprocess.run(
                ["snap", "list"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in res.stdout.splitlines()[1:]:
                cols = line.split()
                if len(cols) >= 2:
                    apps.append({
                        "name": cols[0],
                        "id": cols[0],
                        "version": cols[1],
                        "source": "Snap",
                    })
        except (OSError, subprocess.SubprocessError):
            pass

    # 3. Manually installed APT packages (keeps inventory readable vs 2,500+ libs)
    if shutil.which("apt-mark") and shutil.which("dpkg-query"):
        try:
            manual_res = subprocess.run(
                ["apt-mark", "showmanual"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            manual_pkgs = [p.strip() for p in manual_res.stdout.splitlines() if p.strip()][:limit]
            if manual_pkgs:
                dpkg_res = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"] + manual_pkgs,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                for line in dpkg_res.stdout.splitlines():
                    if "\t" in line:
                        pkg, ver = line.split("\t", 1)
                        apps.append({
                            "name": pkg.strip(),
                            "id": pkg.strip(),
                            "version": ver.strip(),
                            "source": "APT (Manual)",
                        })
        except (OSError, subprocess.SubprocessError):
            pass

    return apps
