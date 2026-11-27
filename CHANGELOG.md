# Changelog

All notable changes to **Linux / Zorin Software Update Manager & Intrusion Shield** will be documented in this file.

## [1.2.1] - 2026-11-27 — Tarball Extraction, Git Repo Strict Matching & Dual-Boot NTFS Alignment

### Fixed
- **Telegram / Tarball `[Errno 17] File exists` Fix (`core/appimage_engine.py`):** Added `_safe_extract_tar_strip_root()` which skips the single top-level directory entry itself (e.g., `Telegram/`) and cleanly unlinks existing files before extraction so updating `Telegram Desktop` and `Antigravity` tarballs never collides with existing binaries.
- **Git AI Repo False-Positive & Divergent Branch Fix (`core/appimage_engine.py`):** Tightened `_scan_git_ai_repos()` to require *all* marker files (or matching folder name + marker) so unrelated Python repos containing `main.py` are never misidentified as ComfyUI, and switched `git pull` to `git pull --rebase --autostash` to cleanly reconcile divergent branches.
- **Dual-Boot Windows NTFS & Shared AI Model Vault Alignment (`core/appimage_engine.py`):** Pruned Windows OS and shared model vault directories (`Windows`, `Program Files`, `ProgramData`, `$Recycle.Bin`, `System Volume Information`, `AI_Models`, `huggingface`) from deep app discovery so Linux+Windows dual-boot mounts stay fast and untouched.

## [1.2.0] - 2026-11-25 — Deep Discovery, AI Services & GUI Polish

### Added
- **3-Level Deep Bounded App Discovery (`core/appimage_engine.py`):** Recursively scans user-configured secondary drives and custom folders up to 3 levels deep (pruning `.git`, `node_modules`, `.venv`, `models`, `blobs`, caches) so organized subdirectories like `Applications/Telegram` or `Tools/Obsidian` are discovered automatically with zero hardcoded paths.
- **Ollama Local LLM Service Updater (`core/package_engine.py`):** Compares `ollama --version` against live upstream GitHub releases (`ollama/ollama`) and runs the official installer + systemd restart only when a newer version is available.
- **Git-Managed Local AI Repo Engine (`providers.json` + `core/appimage_engine.py`):** Auto-discovers installed **SwarmUI**, **ComfyUI**, **Automatic1111**, and **Text Generation WebUI** repositories, checks upstream commits (`git fetch` + `rev-list`), and updates cleanly via `git pull --autostash`.
- **Completed Provider Strategies:** Implemented `github_release_zip` (**balenaEtcher**), `antigravity_cloud_tar` (**Antigravity Core 2.0** & **Antigravity IDE**), and smart on-disk AppImage version matching to prevent false-positive update alerts.
- **Desktop GUI Polish (`ui/gui_app.py` & `core/privilege_helper.py`):**
  - Enforced upfront Polkit (`pkexec`) administrator authentication on Desktop icon startup (while keeping the GUI process unprivileged as `$USER`).
  - Added click-to-sort column headers (`▲` / `▼`) with natural numeric/version sorting across all table tabs.
  - Added draggable `PanedWindow` dividers, vertical + horizontal scrollbars, and resizable columns across all tabs.

## [1.1.0] - 2026-11-21 — Universal Linux Distro Support

### Added
- **Multi-Distro Native Package Engine (`core/package_engine.py`):**
  - **DNF / DNF5** support for **Fedora, RHEL, Nobara, Rocky, and AlmaLinux** (`dnf check-update` / `dnf upgrade -y`).
  - **Pacman** support for **Arch Linux, Manjaro, EndeavourOS, and CachyOS** (`checkupdates` / `pacman -Qu` with Arch-safe full-sync `pacman -Syu` guard to prevent partial-upgrade library breakage).
  - **Zypper** support for **openSUSE Tumbleweed (`zypper dup`) and Leap (`zypper up`)**.
  - Unified `scan_system_updates()` and `refresh_system_cache()` dispatcher with dynamic GUI/CLI labels (`Refresh APT / DNF / Pacman / Zypper Cache`).
- **Universal Firewall Backend (`core/network_auditor.py`):**
  - Auto-detects **`ufw`** (Debian/Ubuntu/Zorin/Arch) OR **`firewalld`** (`firewall-cmd` on Fedora/RHEL/openSUSE) for 1-click LAN port blocking.
  - Guards `systemctl` calls so non-systemd distributions (Alpine, Void, Artix, Devuan) never crash.
- **Cross-Desktop Installer & Dialogs (`install.sh` & `core/privilege_helper.py`):**
  - Auto-detects `apt`, `dnf`/`dnf5`, `pacman`, `zypper`, and `apk` when offering to install Tkinter for Desktop GUI mode.
  - Added **KDE Plasma `kdialog`** fallback alongside GNOME `zenity`.
  - Added **`doas` and `run0`** elevation fallbacks alongside `pkexec` and `sudo`.
  - Replaced Debian-only `x-terminal-emulator` in `.desktop` actions with a portable terminal resolver (`xdg-terminal-exec`, `gnome-terminal`, `konsole`, `xfce4-terminal`, `kitty`, `alacritty`, `xterm`).
- **Universal Installed Software Inventory & Architecture Guards:**
  - `specs_collector.py` now inventories explicitly installed **Pacman (`pacman -Qe`)** and **RPM (`rpm -qa`)** packages alongside APT, Flatpak, and Snap, and reports active `package_manager` and `firewall_backend`.
  - `appimage_engine.py` checks `platform.machine()` (`x86_64`/`amd64`) and `dpkg` availability before scanning `.deb`-only providers so ARM64 and non-Debian hosts run cleanly.
  - `rollback_manager.py` provides distro-specific Timeshift/Snapper install hints.

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
