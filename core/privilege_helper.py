"""Least-privilege elevation wrapper, APT lock waiter, and desktop utilities.

Security Principle:
  The GUI and CLI always execute as the regular user ($USER). Only specific
  privileged system commands (apt, dpkg, snap, ufw, timeshift) are elevated
  via `pkexec` (in GUI mode) or `sudo` (in CLI mode).
"""

from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, Sequence

_SUDO_KEEPALIVE_STARTED = False


def _sudo_keepalive_loop() -> None:
    """Refresh cached sudo ticket in the background while the app is running."""
    while True:
        time.sleep(55)
        try:
            res = subprocess.run(
                ["sudo", "-n", "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if res.returncode != 0:
                break
        except (OSError, subprocess.SubprocessError):
            break


def authenticate_sudo_upfront(require_admin: bool = True) -> bool:
    """Authenticate administrator privileges upfront following Linux least-privilege rules.

    - Never elevates the Python process or GUI itself to UID 0 (which breaks
      Wayland, GTK/Tk themes, Flatpak user installs, and ~/.config ownership).
    - In interactive terminal sessions, caches a sudo ticket once via `sudo -v`
      and keeps it alive in a background daemon thread for the session.
    - In pure GUI sessions (no TTY), relies on Polkit (`pkexec`) per privileged
      action, or prompts upfront via Polkit if `pkexec` is available.
    """
    global _SUDO_KEEPALIVE_STARTED
    if is_root():
        return True

    if sys.stdin.isatty() and shutil.which("sudo"):
        # Check if sudo ticket is already cached
        check = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if check.returncode != 0:
            print("🔑 Administrator authentication is required for system updates (APT, Snap, UFW, Timeshift).")
            print("   (Following Linux security rules, the app stays unprivileged and only elevates system tasks.)")
            res = subprocess.run(["sudo", "-v"])
            if res.returncode != 0:
                if require_admin:
                    print("❌ Administrator authentication failed or was cancelled.")
                return False
        if not _SUDO_KEEPALIVE_STARTED:
            _SUDO_KEEPALIVE_STARTED = True
            threading.Thread(target=_sudo_keepalive_loop, daemon=True).start()
        return True

    # Non-TTY graphical launch: keep GUI running as $USER; pkexec handles elevation cleanly
    return True


def detect_system_package_manager() -> str | None:
    """Detect the primary native Linux system package manager."""
    if shutil.which("apt"):
        return "apt"
    if shutil.which("dnf") or shutil.which("dnf5"):
        return "dnf"
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("zypper"):
        return "zypper"
    if shutil.which("apk"):
        return "apk"
    return None


def find_terminal_emulator() -> str | None:
    """Resolve a portable Linux terminal emulator across GNOME, KDE, XFCE, and tiling WMs."""
    for term in (
        "xdg-terminal-exec",
        "x-terminal-emulator",
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "mate-terminal",
        "kitty",
        "alacritty",
        "wezterm",
        "xterm",
    ):
        found = shutil.which(term)
        if found:
            return found
    return None


def ensure_tkinter_available(interactive: bool = True) -> bool:
    """Ensure Tkinter is installed for GUI mode, offering automatic installation with user consent."""
    try:
        import tkinter  # noqa: F401
        return True
    except ImportError:
        pass

    # Determine distro package command
    if shutil.which("apt"):
        pkg_name = "python3-tk"
        install_cmd = ["apt", "install", "-y", pkg_name]
        refresh_cmd: list[str] | None = ["apt", "update"]
    elif shutil.which("dnf") or shutil.which("dnf5"):
        dnf_bin = "dnf5" if shutil.which("dnf5") else "dnf"
        pkg_name = "python3-tkinter"
        install_cmd = [dnf_bin, "install", "-y", pkg_name]
        refresh_cmd = None
    elif shutil.which("pacman"):
        pkg_name = "tk"
        install_cmd = ["pacman", "-S", "--noconfirm", pkg_name]
        refresh_cmd = None
    elif shutil.which("zypper"):
        pkg_name = "python3-tk"
        install_cmd = ["zypper", "--non-interactive", "install", pkg_name]
        refresh_cmd = None
    elif shutil.which("apk"):
        pkg_name = "py3-tkinter"
        install_cmd = ["apk", "add", pkg_name]
        refresh_cmd = None
    else:
        print("[Notice] Python Tkinter is not installed and no supported package manager was detected.")
        return False

    if not interactive:
        return False

    approved = False
    mode = "cli"
    if sys.stdin.isatty():
        print(f"\n[Setup] Python Tkinter (`{pkg_name}`) is required for Desktop GUI mode.")
        ans = input(f"Would you like to install `{pkg_name}` automatically now? [Y/n]: ").strip().lower()
        approved = ans in ("", "y", "yes")
        mode = "cli"
    elif has_gui_display() and shutil.which("zenity"):
        res = subprocess.run(
            [
                "zenity", "--question",
                "--title=Software Update Manager — GUI Setup",
                f"--text=Python Tkinter ({pkg_name}) is required for Desktop GUI mode.\n\nInstall {pkg_name} automatically now?",
                "--ok-label=Install Now",
                "--cancel-label=Cancel",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        approved = res.returncode == 0
        mode = "gui"
    elif has_gui_display() and shutil.which("kdialog"):
        res = subprocess.run(
            [
                "kdialog", "--yesno",
                f"Python Tkinter ({pkg_name}) is required for Desktop GUI mode.\n\nInstall {pkg_name} automatically now?",
                "--title", "Software Update Manager — GUI Setup",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        approved = res.returncode == 0
        mode = "gui"

    if not approved:
        return False

    if mode == "cli":
        if not authenticate_sudo_upfront(require_admin=True):
            return False

    if refresh_cmd:
        ok_lock, lock_msg = wait_for_apt_locks(timeout_seconds=60, log_cb=print if mode == "cli" else None)
        if not ok_lock:
            print(f"⚠️ {lock_msg}")
            return False
        print(f"📦 Updating package lists and installing {pkg_name}...")
        run_command(refresh_cmd, privileged=True, mode=mode, timeout=180, stream_cb=print if mode == "cli" else None)

    rc, out = run_command(
        install_cmd,
        privileged=True,
        mode=mode,
        timeout=240,
        stream_cb=print if mode == "cli" else None,
    )
    if rc != 0:
        print(f"❌ Failed to install {pkg_name} (exit {rc}): {out[-300:]}")
        return False

    # Re-verify import after installation
    try:
        import importlib
        importlib.invalidate_caches()
        import tkinter  # noqa: F401
        print(f"✅ {pkg_name} installed successfully! Launching Desktop GUI...\n")
        return True
    except ImportError:
        print(f"⚠️ {pkg_name} installed, but tkinter could not be loaded in this Python runtime.")
        return False


APT_LOCK_FILES = (
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/lib/apt/lists/lock",
)


def is_root() -> bool:
    """Return True if current process is running as UID 0."""
    return os.geteuid() == 0


def has_gui_display() -> bool:
    """Return True if an X11 or Wayland display session is active."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def get_session_type() -> str:
    """Return 'wayland', 'x11', or 'headless'."""
    session = os.environ.get("XDG_SESSION_TYPE", "").lower()
    if session in ("wayland", "x11"):
        return session
    if os.environ.get("WAYLAND_DISPLAY"):
        return "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return "headless"


def build_privileged_cmd(cmd: Sequence[str], mode: str = "cli") -> list[str]:
    """Wrap a command with pkexec (GUI) or sudo/doas/run0 (CLI) if not already root."""
    cmd_list = list(cmd)
    if is_root():
        return cmd_list
    if mode == "gui" and shutil.which("pkexec") and has_gui_display():
        return ["pkexec"] + cmd_list
    if shutil.which("sudo"):
        return ["sudo"] + cmd_list
    if shutil.which("doas"):
        return ["doas"] + cmd_list
    if shutil.which("run0"):
        return ["run0"] + cmd_list
    return cmd_list


def wait_for_apt_locks(
    timeout_seconds: int = 60,
    log_cb: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """Wait for APT/DPKG lock files to become free before running apt/dpkg.

    Uses non-blocking fuser checks (or read-only lock checks) to avoid crashes
    when unattended-upgrades or GNOME Software is running in the background.
    """
    start = time.monotonic()
    fuser_bin = shutil.which("fuser")

    while True:
        busy_lock = None
        for lock_file in APT_LOCK_FILES:
            if not os.path.exists(lock_file):
                continue
            if fuser_bin:
                res = subprocess.run(
                    [fuser_bin, lock_file],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if res.returncode == 0:
                    busy_lock = lock_file
                    break
            else:
                # Pure Python fallback check if readable/writable
                try:
                    with open(lock_file, "r+b") as fh:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except BlockingIOError:
                    busy_lock = lock_file
                    break
                except OSError:
                    # Permission denied on root-owned lock file is expected for non-root
                    pass

        if not busy_lock:
            return True, "APT locks are clear."

        elapsed = int(time.monotonic() - start)
        if elapsed >= timeout_seconds:
            return False, f"Timed out after {timeout_seconds}s waiting for lock: {busy_lock}"

        if log_cb:
            log_cb(f"Waiting for background package manager lock ({busy_lock})... [{elapsed}s/{timeout_seconds}s]")
        time.sleep(3)


def run_command(
    cmd: Sequence[str],
    privileged: bool = False,
    mode: str = "cli",
    timeout: int = 600,
    stream_cb: Callable[[str], None] | None = None,
) -> tuple[int, str]:
    """Execute a command safely without shell=True, optionally streaming output."""
    full_cmd = build_privileged_cmd(cmd, mode=mode) if privileged else list(cmd)
    output_lines: list[str] = []

    try:
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            clean = line.rstrip("\r\n")
            output_lines.append(clean)
            if stream_cb:
                stream_cb(clean)
        proc.wait(timeout=timeout)
        return proc.returncode, "\n".join(output_lines)
    except subprocess.TimeoutExpired:
        proc.kill()
        return 124, "\n".join(output_lines) + "\n[Command timed out]"
    except FileNotFoundError as exc:
        return 127, f"Command not found: {exc}"
    except OSError as exc:
        return 1, f"OS error executing command: {exc}"


def send_notification(title: str, message: str, urgency: str = "normal") -> None:
    """Send a native Linux desktop notification if notify-send is available."""
    if not has_gui_display():
        return
    notify_bin = shutil.which("notify-send")
    if not notify_bin:
        return
    try:
        subprocess.run(
            [notify_bin, "-u", urgency, "-i", "system-software-update", title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def copy_to_clipboard(text: str) -> tuple[bool, str]:
    """Copy text to Linux clipboard (supports Wayland wl-copy and X11 xclip/xsel)."""
    session = get_session_type()
    candidates: list[list[str]] = []
    if session == "wayland" and shutil.which("wl-copy"):
        candidates.append(["wl-copy"])
    if shutil.which("xclip"):
        candidates.append(["xclip", "-selection", "clipboard"])
    if shutil.which("xsel"):
        candidates.append(["xsel", "--clipboard", "--input"])
    if shutil.which("wl-copy") and ["wl-copy"] not in candidates:
        candidates.append(["wl-copy"])

    for cmd in candidates:
        try:
            proc = subprocess.run(
                cmd,
                input=text,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if proc.returncode == 0:
                return True, f"Copied via {cmd[0]}"
        except (OSError, subprocess.SubprocessError):
            continue
    return False, "No Linux clipboard utility found (install wl-clipboard or xclip)."
