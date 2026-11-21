# Changelog

All notable changes to **Linux / Zorin Software Update Manager & Intrusion Shield** will be documented in this file.

## [1.0.0] - 2026-11-21

### Added
- **Dual-Mode Interface (GUI + CLI + Headless + MCP):** Unified `update_manager.py` supporting `--gui`, `--cli`, `--check`, `--upgrade-all`, `--audit-network`, `--specs`, `--configure`, `--snapshot`, and `--mcp`.
- **Automatic `python3-tk` Setup:** Prompts user permission to install `python3-tk` automatically when Desktop GUI mode is chosen on fresh Debian/Ubuntu/Zorin installs, with graceful CLI fallback.
- **Least-Privilege Security Model:** Keeps the GUI and CLI running as `$USER`, caching `sudo -v` upfront with keepalive in CLI mode and elevating via Polkit (`pkexec`) in GUI mode.
- **Dynamic Multi-Drive & Secondary Storage Wizard:** Automatically inspects `/proc/mounts` for physical non-root drives (`/media/...`, `/mnt/...`) and persists user-selected custom paths in `~/.config/software-update-manager/config.json`.
- **Hybrid Package Engine & Smart Bandwidth Caching:**
  - Parallel scans for APT (with dpkg lock waiter), Flatpak, Snap, and Developer SDKs (`rustup`, `uv`, `bun`, `pnpm`, `flutter`) with live upstream semver comparison.
  - Declarative `providers.json` AppImage & standalone updater (Obsidian, Joplin, LM Studio, AnythingLLM, Telegram Desktop, balenaEtcher, Docker Desktop release-notes build scraper) with ETag/Redirect/Tag/Build-ID caching and SHA-256 verification.
- **1-Click System Rollback:** Auto-detects Timeshift or Snapper for pre-update snapshots.
- **Linux Network Boundary Sentinel:** Audits listening TCP sockets via `ss -tlnp` (with `/proc/net/tcp` fallback) to flag `0.0.0.0` LAN exposure on local AI/dev ports with 1-click UFW port blocking.
- **AI Diagnose Launchpad & Zero-Port Stdio MCP Server:** 1-click Web AI links, dynamic local AI `.desktop` auto-discovery, IPI output sanitization, and 4-tier JSON-RPC stdio MCP bridge.
- **Built-in Help & User Guide Tab:** Full documentation, safety checklist, and visual branding with custom banner and circular app icon.
