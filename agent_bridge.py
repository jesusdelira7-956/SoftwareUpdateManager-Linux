"""Zero-Port Stdio MCP Server & 4-Tier Permission Gatekeeper for Linux.

100% Python Standard Library (sys.stdin / sys.stdout JSON-RPC 2.0).
Opens ZERO TCP ports (immune to LAN/0.0.0.0 network probes).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from core.config_manager import APP_VERSION, load_config
from core.network_auditor import audit_listening_ports, get_ufw_status
from core.scanner import scan_all_updates
from core.security_auditor import sanitize_for_ai
from core.specs_collector import collect_system_specs

PROJECT_ROOT = Path(__file__).resolve().parent
PERMISSIONS_FILE = PROJECT_ROOT / "agent_permissions.json"

TOOLS_MANIFEST = [
    {
        "name": "get_system_specs",
        "description": "Return sanitized Linux OS, kernel, CPU, RAM, GPU, and mounted disk specifications.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "scan_pending_updates",
        "description": "Scan APT, Flatpak, Snap, Dev SDKs, and configured AppImages for pending updates (read-only).",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "audit_network_ports",
        "description": "Run the Linux Network Boundary Sentinel to inspect listening TCP ports and 0.0.0.0 LAN exposure.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_storage_config",
        "description": "Return configured custom application directories and update source toggles.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
]


def _load_active_tier() -> int:
    if PERMISSIONS_FILE.exists():
        try:
            data = json.loads(PERMISSIONS_FILE.read_text(encoding="utf-8"))
            return int(data.get("active_tier", 1))
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    return 1


def _handle_tool_call(name: str, _args: dict[str, Any]) -> str:
    tier = _load_active_tier()
    if tier <= 0:
        return json.dumps({"error": "Agent Bridge is disabled (Tier 0: Air-Gapped)."})

    if name == "get_system_specs":
        return sanitize_for_ai(json.dumps(collect_system_specs(), indent=2))

    if name == "scan_pending_updates":
        items = scan_all_updates(load_config())
        return sanitize_for_ai(json.dumps([i.to_dict() for i in items], indent=2), max_length=12000)

    if name == "audit_network_ports":
        payload = {
            "ufw_status": get_ufw_status(),
            "listening_ports": audit_listening_ports(),
        }
        return sanitize_for_ai(json.dumps(payload, indent=2), max_length=12000)

    if name == "get_storage_config":
        return sanitize_for_ai(json.dumps(load_config(), indent=2))

    return json.dumps({"error": f"Unknown tool: {name}"})


def _send_response(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def run_mcp_stdio_server() -> int:
    """Serve MCP JSON-RPC 2.0 messages line-by-line over stdin/stdout."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}

        if method == "initialize":
            _send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "linux-software-update-manager",
                        "version": APP_VERSION,
                    },
                    "capabilities": {"tools": {}},
                },
            })
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS_MANIFEST},
            })
        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}
            text_out = _handle_tool_call(tool_name, tool_args)
            _send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text_out}]},
            })
        elif req_id is not None:
            _send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })
    return 0


if __name__ == "__main__":
    raise SystemExit(run_mcp_stdio_server())
