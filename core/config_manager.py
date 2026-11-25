"""XDG-compliant configuration manager and dynamic Linux multi-drive detector.

Zero third-party dependencies (100% Python Standard Library).
Never hardcodes personal usernames or drive labels.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

APP_NAME = "software-update-manager"
APP_VERSION = "1.2.0"

# XDG Base Directory paths
XDG_CONFIG_HOME = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
XDG_CACHE_HOME = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
XDG_STATE_HOME = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))

CONFIG_DIR = XDG_CONFIG_HOME / APP_NAME
CACHE_DIR = XDG_CACHE_HOME / APP_NAME
LOG_DIR = XDG_STATE_HOME / APP_NAME / "logs"

CONFIG_FILE = CONFIG_DIR / "config.json"
CACHE_STATE_FILE = CACHE_DIR / "version_cache.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "version": APP_VERSION,
    "setup_completed": False,
    "preferred_mode": "ask",  # "gui", "cli", or "ask"
    "custom_app_dirs": [],
    "enable_apt": True,
    "enable_flatpak": True,
    "enable_snap": True,
    "enable_dev_sdks": True,
    "enable_appimages": True,
    "enable_docker_desktop": True,
    "enable_ollama": True,
    "auto_snapshot_before_batch": False,
    "apt_lock_timeout_seconds": 60,
}

# Pseudo-filesystems and system mount prefixes to ignore during drive discovery
_IGNORED_FSTYPES = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
    "pstore", "securityfs", "debugfs", "tracefs", "configfs", "fusectl",
    "mqueue", "hugetlbfs", "autofs", "efivarfs", "squashfs", "overlay",
    "ramfs", "rpc_pipefs", "nsfs", "bpf", "binfmt_misc", "fuse.portal",
    "fuse.gvfsd-fuse",
}

_IGNORED_MOUNT_PREFIXES = (
    "/proc", "/sys", "/dev", "/run/user", "/snap", "/boot", "/var",
    "/etc", "/usr", "/tmp", "/lib", "/bin", "/sbin", "/root", "/opt",
)


def _mount_priority(mountpoint: str) -> tuple[int, int]:
    """Prefer standard external/secondary mount roots (/media, /run/media, /mnt) over arbitrary paths."""
    if mountpoint.startswith(("/media/", "/run/media/")):
        return (0, len(mountpoint))
    if mountpoint.startswith("/mnt/"):
        return (1, len(mountpoint))
    return (2, len(mountpoint))


def ensure_directories() -> None:
    """Ensure XDG config, cache, and log directories exist."""
    for d in (CONFIG_DIR, CACHE_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)


def get_logger(name: str = "sum_linux") -> logging.Logger:
    """Return a structured file + stream audit logger."""
    ensure_directories()
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    log_file = LOG_DIR / f"updater_{datetime.now().strftime('%Y%m%d')}.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(fh)
    return logger


def detect_secondary_drives() -> list[dict[str, Any]]:
    """Dynamically inspect /proc/mounts to discover non-root physical storage drives.

    Filters out pseudo-filesystems, system directories, and bind-mounted subfolders,
    returning one clean entry per mounted external/secondary partition.
    """
    drives: list[dict[str, Any]] = []
    seen_devices: dict[str, dict[str, Any]] = {}
    mounts_path = Path("/proc/mounts")

    if not mounts_path.exists():
        return drives

    try:
        lines = mounts_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return drives

    root_device = ""
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "/":
            root_device = parts[0]
            break

    home_str = str(Path.home())

    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        device, raw_mount, fstype = parts[0], parts[1], parts[2]
        mountpoint = raw_mount.replace("\\040", " ")

        if mountpoint == "/" or device == root_device:
            continue
        if not device.startswith("/dev/") or device.startswith("/dev/loop"):
            continue
        if fstype in _IGNORED_FSTYPES:
            continue
        if any(mountpoint == p or mountpoint.startswith(p + "/") for p in _IGNORED_MOUNT_PREFIXES):
            continue
        # Skip bind-mounts inside $HOME (e.g. offloaded caches)
        if mountpoint == home_str or mountpoint.startswith(home_str + "/"):
            continue

        mp_path = Path(mountpoint)
        if not mp_path.is_dir() or not os.access(mountpoint, os.R_OK):
            continue

        # Keep the highest-priority (standard /media or /mnt, shortest) mountpoint per physical block device
        existing = seen_devices.get(device)
        if existing and _mount_priority(existing["mountpoint"]) <= _mount_priority(mountpoint):
            continue

        try:
            usage = shutil.disk_usage(mountpoint)
            total_gb = round(usage.total / (1024 ** 3), 1)
            free_gb = round(usage.free / (1024 ** 3), 1)
        except OSError:
            total_gb, free_gb = 0.0, 0.0

        seen_devices[device] = {
            "device": device,
            "mountpoint": mountpoint,
            "fstype": fstype,
            "total_gb": total_gb,
            "free_gb": free_gb,
        }

    drives = sorted(seen_devices.values(), key=lambda d: d["mountpoint"])
    return drives


def load_config() -> dict[str, Any]:
    """Load user configuration from XDG config path, merging any new defaults."""
    ensure_directories()
    config = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            stored = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                config.update(stored)
        except (OSError, json.JSONDecodeError):
            pass
    return config


def save_config(config: dict[str, Any]) -> None:
    """Persist user configuration safely to XDG config path."""
    ensure_directories()
    tmp_path = CONFIG_FILE.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(CONFIG_FILE)


def load_version_cache() -> dict[str, Any]:
    """Load cached ETags / version tags / build IDs for bandwidth optimization."""
    ensure_directories()
    if CACHE_STATE_FILE.exists():
        try:
            data = json.loads(CACHE_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def save_version_cache(cache: dict[str, Any]) -> None:
    """Save cached ETags / version tags / build IDs."""
    ensure_directories()
    tmp_path = CACHE_STATE_FILE.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(CACHE_STATE_FILE)


def get_search_directories(config: dict[str, Any]) -> list[Path]:
    """Return deduplicated list of directories to scan for standalone apps/AppImages."""
    candidates: list[Path] = [
        Path.home() / "Applications",
        Path.home() / ".local" / "bin",
    ]
    for raw_dir in config.get("custom_app_dirs", []):
        expanded = Path(os.path.expanduser(raw_dir))
        if expanded.is_dir():
            candidates.append(expanded)

    unique: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        resolved = str(p)
        if resolved not in seen and p.is_dir():
            seen.add(resolved)
            unique.append(p)
    return unique
