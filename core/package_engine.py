"""Hybrid Linux Package & Developer SDK Scanner and Sequential Updater.

Supports:
  - APT (with lock waiter and Ubuntu phased/kept-back package awareness)
  - Flatpak (user & system apps)
  - Snap (canonical snapd refresh)
  - Developer SDKs (rustup, uv, bun, pnpm, flutter)
  - Ollama local inference service

100% Python Standard Library.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable

from core.privilege_helper import run_command, wait_for_apt_locks
from core.security_auditor import evaluate_package_trust

_USER_AGENT = "SoftwareUpdateManager-Linux/1.0"
_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse_semver(text: str) -> tuple[int, int, int] | None:
    """Extract the first major.minor.patch tuple from a version string."""
    m = _SEMVER_RE.search(text or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _fetch_remote_json(url: str, timeout: int = 8) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data if isinstance(data, dict) else None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None


@dataclass
class UpdateItem:
    id: str
    name: str
    source: str          # APT, Flatpak, Snap, Dev SDK, AppImage, Standalone, Docker
    current_version: str
    available_version: str
    trust_status: str    # TRUSTED, WARNING, BLOCKED
    trust_reasons: list[str]
    needs_root: bool
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def scan_apt_updates(config: dict[str, Any]) -> list[UpdateItem]:
    """Scan APT for upgradable packages (non-privileged read of apt cache)."""
    if not config.get("enable_apt", True) or not shutil.which("apt"):
        return []

    items: list[UpdateItem] = []
    try:
        res = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            timeout=20,
            env={**os.environ, "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return items

    # Format: pkg/noble-updates 1.2.3 amd64 [upgradable from: 1.2.2]
    pattern = re.compile(r"^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s+([^\]]+)\]")
    for line in res.stdout.splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        pkg_name, avail_ver, curr_ver = m.group(1), m.group(2), m.group(3)
        trust = evaluate_package_trust(name=pkg_name, pkg_id=pkg_name)
        items.append(UpdateItem(
            id=f"apt:{pkg_name}",
            name=pkg_name,
            source="APT",
            current_version=curr_ver,
            available_version=avail_ver,
            trust_status=trust["status"],
            trust_reasons=trust["reasons"],
            needs_root=True,
            metadata={"package": pkg_name},
        ))
    return items


def refresh_apt_index(
    mode: str = "cli",
    timeout_lock: int = 60,
    stream_cb: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """Run `apt update` safely after waiting for any background dpkg locks."""
    if not shutil.which("apt"):
        return False, "APT is not installed on this system."
    ok, msg = wait_for_apt_locks(timeout_seconds=timeout_lock, log_cb=stream_cb)
    if not ok:
        return False, msg
    rc, out = run_command(["apt", "update"], privileged=True, mode=mode, timeout=180, stream_cb=stream_cb)
    return rc == 0, out


def scan_flatpak_updates(config: dict[str, Any]) -> list[UpdateItem]:
    """Scan Flatpak for available application updates."""
    if not config.get("enable_flatpak", True) or not shutil.which("flatpak"):
        return []

    items: list[UpdateItem] = []
    try:
        res = subprocess.run(
            ["flatpak", "remote-ls", "--updates", "--app", "--columns=name,application,version"],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (OSError, subprocess.SubprocessError):
        return items

    for line in res.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        name = cols[0].strip()
        app_id = cols[1].strip()
        avail = cols[2].strip() if len(cols) > 2 and cols[2].strip() else "latest"
        trust = evaluate_package_trust(name=name, pkg_id=app_id)
        items.append(UpdateItem(
            id=f"flatpak:{app_id}",
            name=name,
            source="Flatpak",
            current_version="installed",
            available_version=avail,
            trust_status=trust["status"],
            trust_reasons=trust["reasons"],
            needs_root=False,
            metadata={"app_id": app_id},
        ))
    return items


def scan_snap_updates(config: dict[str, Any]) -> list[UpdateItem]:
    """Scan Snap for pending package refreshes."""
    if not config.get("enable_snap", True) or not shutil.which("snap"):
        return []

    items: list[UpdateItem] = []
    try:
        res = subprocess.run(
            ["snap", "refresh", "--list"],
            capture_output=True,
            text=True,
            timeout=25,
            env={**os.environ, "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return items

    lines = [l for l in res.stdout.splitlines() if l.strip()]
    if len(lines) <= 1:
        return items

    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 2:
            continue
        snap_name, avail_ver = cols[0], cols[1]
        trust = evaluate_package_trust(name=snap_name, pkg_id=snap_name)
        items.append(UpdateItem(
            id=f"snap:{snap_name}",
            name=snap_name,
            source="Snap",
            current_version="installed",
            available_version=avail_ver,
            trust_status=trust["status"],
            trust_reasons=trust["reasons"],
            needs_root=True,
            metadata={"snap_name": snap_name},
        ))
    return items


def _find_binary(name: str, extra_dirs: list[Path] | None = None) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    home = Path.home()
    candidates = [
        home / ".cargo" / "bin" / name,
        home / ".local" / "bin" / name,
        home / ".bun" / "bin" / name,
    ]
    if extra_dirs:
        for d in extra_dirs:
            candidates.append(d / name)
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)
    return None


def scan_dev_sdks(config: dict[str, Any]) -> list[UpdateItem]:
    """Detect installed Developer SDKs & CLI runtimes that have genuine newer releases."""
    if not config.get("enable_dev_sdks", True):
        return []

    items: list[UpdateItem] = []

    # 1. Rustup
    rustup = _find_binary("rustup")
    if rustup:
        try:
            res = subprocess.run([rustup, "check"], capture_output=True, text=True, timeout=20)
            if "Update available" in res.stdout:
                items.append(UpdateItem(
                    id="sdk:rustup",
                    name="Rust & Cargo Toolchain (rustup)",
                    source="Dev SDK",
                    current_version="installed",
                    available_version="update available",
                    trust_status="TRUSTED",
                    trust_reasons=[],
                    needs_root=False,
                    metadata={"cmd": [rustup, "update"]},
                ))
        except (OSError, subprocess.SubprocessError):
            pass

    # 2. uv (fast Python package manager)
    uv_bin = _find_binary("uv")
    if uv_bin:
        try:
            ver_res = subprocess.run([uv_bin, "--version"], capture_output=True, text=True, timeout=8)
            local_ver = _parse_semver(ver_res.stdout)
            remote_data = _fetch_remote_json("https://api.github.com/repos/astral-sh/uv/releases/latest")
            remote_tag = (remote_data or {}).get("tag_name", "")
            remote_ver = _parse_semver(remote_tag)
            if local_ver and remote_ver and remote_ver > local_ver:
                items.append(UpdateItem(
                    id="sdk:uv",
                    name="uv Python Package Manager",
                    source="Dev SDK",
                    current_version=".".join(map(str, local_ver)),
                    available_version=".".join(map(str, remote_ver)),
                    trust_status="TRUSTED",
                    trust_reasons=[],
                    needs_root=False,
                    metadata={"cmd": [uv_bin, "self", "update"]},
                ))
        except (OSError, subprocess.SubprocessError):
            pass

    # 3. Bun
    bun_bin = _find_binary("bun")
    if bun_bin:
        try:
            ver_res = subprocess.run([bun_bin, "--version"], capture_output=True, text=True, timeout=8)
            local_ver = _parse_semver(ver_res.stdout)
            remote_data = _fetch_remote_json("https://api.github.com/repos/oven-sh/bun/releases/latest")
            remote_tag = (remote_data or {}).get("tag_name", "")
            remote_ver = _parse_semver(remote_tag)
            if local_ver and remote_ver and remote_ver > local_ver:
                items.append(UpdateItem(
                    id="sdk:bun",
                    name="Bun JS/TS Runtime",
                    source="Dev SDK",
                    current_version=".".join(map(str, local_ver)),
                    available_version=".".join(map(str, remote_ver)),
                    trust_status="TRUSTED",
                    trust_reasons=[],
                    needs_root=False,
                    metadata={"cmd": [bun_bin, "upgrade"]},
                ))
        except (OSError, subprocess.SubprocessError):
            pass

    # 4. pnpm (prefer self-managed ~/.local/share/pnpm/pnpm over static npx wrappers)
    self_managed_pnpm = Path.home() / ".local" / "share" / "pnpm" / "pnpm"
    pnpm_bin = (
        str(self_managed_pnpm)
        if self_managed_pnpm.is_file() and os.access(self_managed_pnpm, os.X_OK)
        else _find_binary("pnpm")
    )
    if pnpm_bin:
        try:
            ver_res = subprocess.run([pnpm_bin, "--version"], capture_output=True, text=True, timeout=10)
            local_ver = _parse_semver(ver_res.stdout)
            remote_data = _fetch_remote_json("https://registry.npmjs.org/pnpm/latest")
            remote_ver = _parse_semver((remote_data or {}).get("version", ""))
            if local_ver and remote_ver and remote_ver > local_ver:
                items.append(UpdateItem(
                    id="sdk:pnpm",
                    name="pnpm Package Manager",
                    source="Dev SDK",
                    current_version=".".join(map(str, local_ver)),
                    available_version=".".join(map(str, remote_ver)),
                    trust_status="TRUSTED",
                    trust_reasons=[],
                    needs_root=False,
                    metadata={"cmd": [pnpm_bin, "self-update"]},
                ))
        except (OSError, subprocess.SubprocessError):
            pass

    # 5. Flutter (non-snap installations only)
    flutter_bin = _find_binary("flutter")
    if flutter_bin and not flutter_bin.startswith("/snap/"):
        try:
            ver_res = subprocess.run([flutter_bin, "--version"], capture_output=True, text=True, timeout=15)
            local_ver = _parse_semver(ver_res.stdout)
            remote_data = _fetch_remote_json("https://api.github.com/repos/flutter/flutter/releases/latest")
            remote_ver = _parse_semver((remote_data or {}).get("tag_name", ""))
            if local_ver and remote_ver and remote_ver > local_ver:
                items.append(UpdateItem(
                    id="sdk:flutter",
                    name="Flutter SDK",
                    source="Dev SDK",
                    current_version=".".join(map(str, local_ver)),
                    available_version=".".join(map(str, remote_ver)),
                    trust_status="TRUSTED",
                    trust_reasons=[],
                    needs_root=False,
                    metadata={"cmd": [flutter_bin, "upgrade"]},
                ))
        except (OSError, subprocess.SubprocessError):
            pass

    return items


def apply_package_update(
    item: UpdateItem,
    mode: str = "cli",
    timeout_lock: int = 60,
    stream_cb: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """Execute a single verified update sequentially."""
    if item.trust_status == "BLOCKED":
        return False, f"Blocked by Pre-Update Trust Gate: {', '.join(item.trust_reasons)}"

    if item.source == "APT":
        ok, msg = wait_for_apt_locks(timeout_seconds=timeout_lock, log_cb=stream_cb)
        if not ok:
            return False, msg
        pkg = item.metadata["package"]
        rc, out = run_command(
            ["apt", "install", "-y", "--only-upgrade", pkg],
            privileged=True,
            mode=mode,
            timeout=300,
            stream_cb=stream_cb,
        )
        return rc == 0, out

    if item.source == "Flatpak":
        app_id = item.metadata["app_id"]
        rc, out = run_command(
            ["flatpak", "update", "-y", app_id],
            privileged=False,
            mode=mode,
            timeout=300,
            stream_cb=stream_cb,
        )
        return rc == 0, out

    if item.source == "Snap":
        snap_name = item.metadata["snap_name"]
        rc, out = run_command(
            ["snap", "refresh", snap_name],
            privileged=True,
            mode=mode,
            timeout=300,
            stream_cb=stream_cb,
        )
        return rc == 0, out

    if item.source == "Dev SDK":
        cmd = item.metadata.get("cmd")
        if not cmd:
            return False, "Missing SDK update command."
        rc, out = run_command(cmd, privileged=False, mode=mode, timeout=300, stream_cb=stream_cb)
        return rc == 0, out

    return False, f"Unsupported package source: {item.source}"
