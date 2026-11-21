"""Unified parallel scan & sequential update orchestrator.

Shared by GUI, Interactive CLI, Headless Cron Mode, and Zero-Port Stdio MCP.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from core.appimage_engine import apply_standalone_update, scan_standalone_updates
from core.config_manager import get_logger, load_config
from core.package_engine import (
    UpdateItem,
    apply_package_update,
    scan_dev_sdks,
    scan_flatpak_updates,
    scan_snap_updates,
    scan_system_updates,
)
from core.privilege_helper import detect_system_package_manager


def scan_all_updates(
    config: dict[str, Any] | None = None,
    progress_cb: Callable[[str], None] | None = None,
) -> list[UpdateItem]:
    """Scan all enabled package sources in parallel and return a unified list."""
    cfg = config or load_config()
    logger = get_logger()
    pm_label = (detect_system_package_manager() or "System").upper()
    tasks = {
        pm_label: lambda: scan_system_updates(cfg),
        "Flatpak": lambda: scan_flatpak_updates(cfg),
        "Snap": lambda: scan_snap_updates(cfg),
        "Dev SDKs": lambda: scan_dev_sdks(cfg),
        "Standalone & AppImages": lambda: scan_standalone_updates(cfg),
    }

    results: list[UpdateItem] = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        future_map = {pool.submit(fn): label for label, fn in tasks.items()}
        for fut in as_completed(future_map):
            label = future_map[fut]
            try:
                found = fut.result()
                results.extend(found)
                if progress_cb:
                    progress_cb(f"Scanned {label}: {len(found)} update(s) found.")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Scan error in %s: %s", label, exc)
                if progress_cb:
                    progress_cb(f"Warning scanning {label}: {exc}")

    results.sort(key=lambda item: (item.source, item.name.lower()))
    return results


def apply_update_item(
    item: UpdateItem,
    mode: str = "cli",
    config: dict[str, Any] | None = None,
    stream_cb: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """Apply a single UpdateItem sequentially using the appropriate engine."""
    cfg = config or load_config()
    timeout_lock = int(cfg.get("apt_lock_timeout_seconds", 60))
    logger = get_logger()
    logger.info("Applying update: %s (%s) [%s -> %s]", item.name, item.source, item.current_version, item.available_version)

    if item.source in ("AppImage", "Standalone", "Docker (.deb)"):
        ok, msg = apply_standalone_update(item, mode=mode, timeout_lock=timeout_lock, stream_cb=stream_cb)
    else:
        ok, msg = apply_package_update(item, mode=mode, timeout_lock=timeout_lock, stream_cb=stream_cb)

    logger.info("Update result for %s: success=%s", item.name, ok)
    return ok, msg
