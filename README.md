# Linux / Zorin Software Update Manager & Intrusion Shield (v1.0.0)

**Dual-Mode (Desktop GUI + Interactive CLI) • Zero Third-Party `pip` Dependencies • Smart Bandwidth Caching • `0.0.0.0` LAN Intrusion Shield • Zero-Port Stdio MCP Bridge**

A portable, zero-dependency software update manager and security dashboard for **Zorin OS, Ubuntu, Debian, Linux Mint, and Pop!_OS**, built with **100% Python Standard Library**.

---

## Key Features

- **Dual-Mode Interface (Your Choice of GUI or CLI):**
  - **Desktop GUI (`--gui`)**: Dark-mode Tkinter dashboard styled for Zorin OS / GNOME.
  - **Interactive CLI (`--cli`)**: Clean ANSI-colorized terminal menu with tables and interactive prompts.
  - **Headless / Cron Mode (`--check`, `--upgrade-all --yes`)**: Unattended automation for systemd timers or cron jobs.
  - **Graceful Fallback**: Automatically falls back to Interactive CLI if run over SSH or if `python3-tk` is not installed.
- **Dynamic Multi-Drive & Secondary Storage Wizard:**
  - Never hardcodes personal paths or drive labels.
  - Automatically scans `/proc/mounts` for external/secondary drives and asks on first run if you store AppImages, portable AI engines, or SDKs in a custom folder.
  - Persists settings cleanly in `~/.config/software-update-manager/config.json`.
- **Hybrid Package Engine + Smart Bandwidth Caching:**
  - **System Packages**: APT (with `/var/lib/dpkg/lock-frontend` waiter), Flatpak, and Snap.
  - **Developer SDKs**: `rustup`, `uv`, `bun`, `pnpm`, and `flutter`.
  - **Declarative Standalone / AppImage Engine (`providers.json`)**: Obsidian, Joplin, LM Studio, AnythingLLM, Telegram, balenaEtcher, and Docker Desktop (dynamic release notes build scraper). Uses **ETag, HTTP Redirect, Release Tag, and Build-ID caching** to avoid gigabytes of redundant downloads.
- **Least-Privilege Security Architecture:**
  - Never runs the GUI as `root`. Elevates *only* system package commands via `pkexec` (GUI) or `sudo` (CLI).
  - **1-Click System Rollback Snapshot**: Auto-detects **Timeshift** or **Snapper** to create pre-update snapshots.
  - **Pre-Update Trust Gate**: Validates SHA-256 checksums and filters packages against `pup_blocklist.json`.
- **Linux Network Boundary Sentinel (`network_auditor.py`):**
  - Parses `ss -tlnp` (with pure-Python `/proc/net/tcp` fallback) to flag local AI engines (Ollama `11434`, LM Studio `1234`, Open WebUI `8081`, ComfyUI `8188`, SwarmUI `7801`, dev ports) accidentally exposed on `0.0.0.0` / `::`.
  - Includes 1-click **UFW firewall hardening**.
- **Zero-Port Stdio MCP Bridge (`--mcp`):**
  - Connects safely to Antigravity IDE, Claude Desktop, or Cursor over `sys.stdin`/`sys.stdout` JSON-RPC 2.0 with **zero open TCP ports** and Indirect Prompt Injection (IPI) output sanitization.

---

## Quick Start

### 1. 1-Click Installer
```bash
chmod +x install.sh
./install.sh
```

### 2. Portable Run (No Installation Needed)
```bash
# Interactive mode picker (choose GUI or CLI)
python3 update_manager.py

# Launch Desktop GUI directly
python3 update_manager.py --gui

# Launch Interactive CLI directly
python3 update_manager.py --cli

# Headless check (exit 0 = up to date, exit 100 = updates available)
python3 update_manager.py --check

# Audit listening TCP ports for 0.0.0.0 LAN exposure
python3 update_manager.py --audit-network

# Configure secondary drives or custom AppImage directories
python3 update_manager.py --configure

# Start Zero-Port Stdio MCP Server
python3 update_manager.py --mcp
```

---

## License

MIT License — see [LICENSE](LICENSE).
