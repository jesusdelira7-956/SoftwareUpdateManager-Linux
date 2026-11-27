# Architecture & Origin Story — Universal Linux Software Update Manager & Intrusion Shield

**Creator:** Jesse In The Lab (`jesusdelira7-956`)  
**Companion Windows Edition:** [SoftwareUpdateManager (Windows 10/11)](https://github.com/jesusdelira7-956/SoftwareUpdateManager)  
**Universal Linux Edition:** [SoftwareUpdateManager-Linux (v1.2.1)](https://github.com/jesusdelira7-956/SoftwareUpdateManager-Linux)  
**Support Development:** [buymeacoffee.com/JesseInTheLab](https://buymeacoffee.com/JesseInTheLab)

---

## 1. Why We Built This

Modern Linux power users and local AI builders rarely live inside a single package manager. A typical workstation mixes:
- Native OS packages (**APT**, **DNF/DNF5**, **Pacman**, or **Zypper**)
- Sandboxed desktop apps (**Flatpak** and **Snap**)
- Developer toolchains (**Rust/rustup**, **uv**, **Bun**, **pnpm**, **Flutter**)
- Local AI inference services & Git repos (**Ollama**, **SwarmUI**, **ComfyUI**, **Automatic1111**)
- Standalone AppImages, tarballs, and zips stored across secondary NVMe/SSD drives (**Obsidian**, **Joplin**, **LM Studio**, **AnythingLLM**, **Telegram Desktop**, **balenaEtcher**, **Docker Desktop**)

Running raw CLI updates across all of these introduces three real problems:
1. **Fragmentation & Bandwidth Waste:** Re-downloading multi-hundred-MB AppImages and tarballs without ETag/redirect/build-ID checks wastes gigabytes of bandwidth, while background updaters collide on `/var/lib/dpkg/lock-frontend`.
2. **Local AI LAN Exposure (`0.0.0.0`):** Local LLM servers and dev dashboards frequently bind to `0.0.0.0` instead of `127.0.0.1`, silently exposing unauthenticated endpoints (`11434`, `1234`, `8081`, `8188`, `8000`) to every device on the local Wi-Fi/LAN.
3. **Supply-Chain & Privilege Risks:** Desktop utilities should never bloat with dozens of third-party `pip` dependencies or run entire GUI processes as `root`.

---

## 2. Core Architectural Principles

| Principle | Implementation |
| :--- | :--- |
| **Zero External `pip` Dependencies** | 100% Python Standard Library (`urllib.request`, `subprocess`, `tarfile`, `zipfile`, `tkinter`, `json`, `hashlib`). Auditable, lightweight, zero PyPI supply-chain bloat. |
| **Linux Least-Privilege Split** | The GUI and CLI always run unprivileged as `$USER` (preserving Wayland, themes, Flatpak user installs, and `~/.config` ownership). Administrator authorization is verified upfront via Polkit (`pkexec`) in GUI mode or `sudo -v` in CLI mode, elevating *only* individual system actions. |
| **Dual-Mode Interface** | Full parity between a dark-mode Tkinter GUI (with click-to-sort columns, draggable `PanedWindow` splitters, and scrollbars) and an ANSI-colorized Interactive CLI + headless cron flags (`--check`, `--upgrade-all --yes`). |
| **Privacy-First Dynamic Discovery** | Zero hardcoded usernames or drive paths. Inspects `/proc/mounts` for physical secondary drives, walks user-configured folders up to 3 levels deep, and automatically prunes heavy/system/dual-boot NTFS folders (`Windows`, `Program Files`, `AI_Models`, `huggingface`, `models`, `node_modules`, `.venv`, `docker-data`). |
| **Zero-Port AI Integration** | Exposes system diagnostics to Claude Desktop, Antigravity IDE, Cursor, and Copilot strictly via `sys.stdin`/`sys.stdout` JSON-RPC 2.0 (Stdio MCP) with Indirect Prompt Injection (IPI) sanitization and **zero open TCP ports**. |

---

## 3. Cross-Distro Compatibility Matrix (v1.2.1)

| Distro Family | Examples | System Package Engine | Firewall Backend | Dialog / Elevation |
| :--- | :--- | :---: | :---: | :---: |
| **Debian / Ubuntu** | Zorin OS, Ubuntu, Debian, Linux Mint, Pop!_OS, Kali | `apt` (with dpkg lock waiter) | `ufw` | `pkexec` / `sudo`, `zenity` |
| **Fedora / RHEL** | Fedora, Nobara, Rocky, AlmaLinux, CentOS | `dnf` / `dnf5` | `firewalld` | `pkexec` / `sudo`, `zenity` / `kdialog` |
| **Arch-based** | Arch Linux, Manjaro, EndeavourOS, CachyOS | `pacman` (Arch-safe `-Syu` sync) | `ufw` / `firewalld` | `pkexec` / `sudo` / `doas` |
| **openSUSE** | Tumbleweed (`dup`), Leap (`up`) | `zypper` | `firewalld` | `pkexec` / `sudo`, `kdialog` / `zenity` |
| **Dual-Boot & Universal** | Any Linux Desktop (GNOME, KDE, XFCE, Hyprland, SSH) | Flatpak, Snap, Dev SDKs, AppImages, Ollama, Git AI Repos | `ss` / `/proc/net/tcp` | Portable terminal resolver |

---

## 4. Key Engineering Hardening Milestones

- **v1.0.0:** Dual-mode GUI + CLI + Zero-Port Stdio MCP Server, dynamic `/proc/mounts` secondary storage wizard, smart ETag/redirect/build-ID bandwidth caching, Timeshift/Snapper 1-click rollback.
- **v1.1.0:** Universal Linux Distro Engine (`dnf`/`dnf5`, `pacman`, `zypper`), auto-detected `ufw` + `firewalld` shield, KDE `kdialog` + `doas`/`run0` fallbacks, portable terminal launcher, and RPM/Pacman software inventory.
- **v1.2.0:** 3-level deep bounded secondary-drive app discovery, Ollama service semver updater, Git-managed local AI repo engine (SwarmUI, ComfyUI, A1111, Text Generation WebUI), `github_release_zip` + `antigravity_cloud_tar` providers, upfront Polkit GUI auth, click-to-sort columns (`▲`/`▼`), and draggable resize panes across all tabs.
- **v1.2.1:** Safe single-root-strip tarball extraction (`_safe_extract_tar_strip_root`) fixing `[Errno 17] File exists` binary collisions (e.g., Telegram Desktop), strict all-marker Git AI repo matching with `git pull --rebase --autostash`, and dual-boot Windows NTFS / shared AI model vault pruning.
