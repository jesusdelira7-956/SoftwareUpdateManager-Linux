"""Linux Network Boundary Sentinel & Intrusion Shield.

100% Python Standard Library.
Scans listening TCP sockets via `ss -tlnp` (with `/proc/net/tcp` fallback) to
detect local AI engines or developer servers accidentally bound to `0.0.0.0`
or `::` (exposed to LAN/Wi-Fi devices) and offers 1-click UFW firewall rules.
"""

from __future__ import annotations

import re
import shutil
import socket
import struct
import subprocess
from pathlib import Path
from typing import Any

from core.privilege_helper import run_command

KNOWN_AI_DEV_PORTS: dict[int, str] = {
    11434: "Ollama Local LLM Daemon",
    1234: "LM Studio Local Server",
    8081: "Open WebUI / Local AI Dashboard",
    8080: "Local Web / Proxy Server",
    8000: "vLLM / FastAPI / Python Dev Server",
    8188: "ComfyUI Image Generation",
    7801: "SwarmUI Image Generation",
    7860: "Gradio / Automatic1111 WebUI",
    8890: "Local App Hub",
    3000: "Node / Next.js / Grafana Dev Server",
    3100: "Local Orchestrator Dashboard",
    5000: "Flask / MLflow / Dev Server",
    5173: "Vite Dev Server",
    49374: "OpenCode Agent Server",
    1919: "FreeToken Local Inference",
}

_PROC_REGEX = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def _classify_address(addr: str) -> tuple[str, str]:
    """Return (exposure_level, label) for a bind address."""
    clean = addr.strip("[]")
    if clean in ("127.0.0.1", "::1", "localhost") or clean.startswith("127."):
        return "ISOLATED", "Localhost (Isolated)"
    if clean in ("0.0.0.0", "*", "::", ":::"):
        return "EXPOSED_LAN", "EXPOSED TO LAN (0.0.0.0 / ::)"
    return "INTERFACE", f"Bound to {clean}"


def _parse_proc_net_tcp() -> list[dict[str, Any]]:
    """Pure-Python fallback parser for /proc/net/tcp (no external binaries)."""
    results: list[dict[str, Any]] = []
    tcp_file = Path("/proc/net/tcp")
    if not tcp_file.exists():
        return results
    try:
        lines = tcp_file.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
    except OSError:
        return results

    for line in lines:
        cols = line.split()
        if len(cols) < 4 or cols[3] != "0A":  # 0A == TCP_LISTEN
            continue
        ip_hex, port_hex = cols[1].split(":")
        port = int(port_hex, 16)
        ip_addr = socket.inet_ntoa(struct.pack("<L", int(ip_hex, 16)))
        exposure, label = _classify_address(ip_addr)
        results.append({
            "port": port,
            "bind_address": ip_addr,
            "process": "unknown",
            "pid": "",
            "service_hint": KNOWN_AI_DEV_PORTS.get(port, "Listening TCP Service"),
            "exposure": exposure,
            "exposure_label": label,
            "is_ai_or_dev_port": port in KNOWN_AI_DEV_PORTS or 3000 <= port <= 5000 or 8000 <= port <= 9000,
        })
    return results


def audit_listening_ports() -> list[dict[str, Any]]:
    """Scan all listening TCP ports and flag LAN exposure risks."""
    ss_bin = shutil.which("ss")
    if not ss_bin:
        return _parse_proc_net_tcp()

    try:
        res = subprocess.run(
            [ss_bin, "-tlnp"],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return _parse_proc_net_tcp()

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    for line in res.stdout.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        local_addr = cols[3]
        if ":" not in local_addr:
            continue
        addr_part, port_str = local_addr.rsplit(":", 1)
        if not port_str.isdigit():
            continue
        port = int(port_str)
        key = (addr_part, port)
        if key in seen:
            continue
        seen.add(key)

        proc_name = "unknown"
        pid = ""
        m = _PROC_REGEX.search(line)
        if m:
            proc_name, pid = m.group(1), m.group(2)

        exposure, label = _classify_address(addr_part)
        is_ai_dev = port in KNOWN_AI_DEV_PORTS or 3000 <= port <= 5000 or 8000 <= port <= 9000

        findings.append({
            "port": port,
            "bind_address": addr_part,
            "process": proc_name,
            "pid": pid,
            "service_hint": KNOWN_AI_DEV_PORTS.get(port, "Listening TCP Service"),
            "exposure": exposure,
            "exposure_label": label,
            "is_ai_or_dev_port": is_ai_dev,
        })

    # Sort exposed AI/dev ports to the top
    findings.sort(
        key=lambda item: (
            0 if (item["exposure"] == "EXPOSED_LAN" and item["is_ai_or_dev_port"]) else
            1 if item["exposure"] == "EXPOSED_LAN" else
            2 if item["is_ai_or_dev_port"] else 3,
            item["port"],
        )
    )
    return findings


def get_ufw_status() -> str:
    """Return UFW installation / active summary without requiring root."""
    if not shutil.which("ufw"):
        return "not_installed"
    # Check systemd unit state (readable by non-root)
    res = subprocess.run(
        ["systemctl", "is-active", "ufw"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return res.stdout.strip() or "unknown"


def block_port_with_ufw(port: int, mode: str = "cli") -> tuple[bool, str]:
    """Block external LAN/WAN inbound traffic to a specific TCP port via UFW."""
    if not shutil.which("ufw"):
        return False, "UFW firewall is not installed (`sudo apt install ufw`)."
    if not (1 <= port <= 65535):
        return False, f"Invalid port number: {port}"

    rc, out = run_command(
        ["ufw", "deny", "in", "proto", "tcp", "to", "any", "port", str(port)],
        privileged=True,
        mode=mode,
        timeout=30,
    )
    if rc == 0:
        return True, f"UFW rule added: blocked external inbound TCP on port {port}."
    return False, f"Failed to add UFW rule (exit {rc}): {out}"
