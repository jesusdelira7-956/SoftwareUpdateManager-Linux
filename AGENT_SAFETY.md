# AI Agent Safety & 4-Tier Permission Model

This application exposes a **Zero-Port Stdio MCP Server** (`update_manager.py --mcp`) communicating strictly over `sys.stdin`/`sys.stdout` JSON-RPC 2.0. It never opens a listening TCP socket (`0.0.0.0` or `127.0.0.1`).

## Permission Tiers (`agent_permissions.json`)
- **Tier 0 (Off / Air-Gapped):** All MCP tool calls are rejected.
- **Tier 1 (Read-Only Diagnostics — Default):** Agents can inspect hardware specs, pending updates, listening ports, and storage configuration. All outputs are sanitized against Indirect Prompt Injection (IPI).
- **Tier 2 (Supervised Remediation):** Write actions require explicit interactive user confirmation.
- **Tier 3 (Autonomous Maintenance):** Time-boxed maintenance with pre-update Timeshift snapshot safety.
