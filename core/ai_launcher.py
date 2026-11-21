"""Dynamic Web AI & Local Installed AI Client Discovery and Launcher.

100% Python Standard Library. Zero hardcoded user paths.
Discovers locally installed AI apps and IDEs from standard XDG .desktop
locations and PATH, and provides 1-click launchers for both web and local AIs.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import webbrowser
from pathlib import Path
from typing import Any

WEB_AI_ASSISTANTS: list[dict[str, str]] = [
    {"id": "gemini", "name": "Google Gemini", "url": "https://gemini.google.com", "color": "#1a73e8"},
    {"id": "claude", "name": "Claude Web", "url": "https://claude.ai", "color": "#d97757"},
    {"id": "chatgpt", "name": "ChatGPT", "url": "https://chatgpt.com", "color": "#10a37f"},
    {"id": "copilot", "name": "Microsoft Copilot", "url": "https://copilot.microsoft.com", "color": "#0078d4"},
    {"id": "perplexity", "name": "Perplexity", "url": "https://www.perplexity.ai", "color": "#20808d"},
]

# Known local AI clients/IDEs to match dynamically from .desktop files or PATH
_LOCAL_AI_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("Antigravity IDE", ("antigravity-ide", "antigravity ide")),
    ("Antigravity Core", ("antigravity 2.0", "antigravity.desktop", "antigravity-2.0")),
    ("Claude Desktop", ("claude-desktop", "claude desktop")),
    ("Cursor AI", ("cursor.desktop", "cursor ai")),
    ("LM Studio", ("lm-studio", "lm studio")),
    ("AnythingLLM", ("anythingllm",)),
    ("Open WebUI", ("open-webui", "open webui")),
    ("Msty Studio", ("msty",)),
    ("SwarmUI", ("swarmui",)),
    ("OpenCode", ("opencode",)),
    ("VS Code", ("visual studio code",)),
    ("Zed Editor", ("zed.desktop", "dev.zed.zed")),
]

_FIELD_CODE_RE = re.compile(r"\s+%[fFuUdDnNickvm]")


def _parse_desktop_file(path: Path) -> dict[str, str] | None:
    """Parse Name, Exec, and Terminal fields from a Linux .desktop entry."""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None

    in_entry = False
    name = ""
    exec_cmd = ""
    terminal = False

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_entry = (line == "[Desktop Entry]")
            continue
        if not in_entry:
            continue
        if line.startswith("Name=") and not name:
            name = line.split("=", 1)[1].strip()
        elif line.startswith("Exec=") and not exec_cmd:
            exec_cmd = line.split("=", 1)[1].strip()
        elif line.startswith("Terminal="):
            terminal = line.split("=", 1)[1].strip().lower() == "true"

    if not name or not exec_cmd:
        return None
    return {
        "name": name,
        "exec": _FIELD_CODE_RE.sub("", exec_cmd).strip(),
        "terminal": "true" if terminal else "false",
        "desktop_file": str(path),
    }


def detect_installed_local_ais() -> list[dict[str, str]]:
    """Scan standard Linux .desktop directories and PATH for installed AI apps."""
    xdg_data = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    search_dirs = [
        xdg_data / "applications",
        Path.home() / "Desktop",
        Path("/usr/share/applications"),
        Path("/var/lib/flatpak/exports/share/applications"),
    ]

    found_by_label: dict[str, dict[str, str]] = {}

    for directory in search_dirs:
        if not directory.is_dir():
            continue
        try:
            desktop_files = sorted(directory.glob("*.desktop"))
        except OSError:
            continue

        for df in desktop_files:
            fname_lower = df.name.lower()
            entry = _parse_desktop_file(df)
            if not entry:
                continue
            name_lower = entry["name"].lower()

            for canonical_label, patterns in _LOCAL_AI_SIGNATURES:
                if canonical_label in found_by_label:
                    continue
                if any(pat in fname_lower or pat in name_lower for pat in patterns):
                    found_by_label[canonical_label] = {
                        "label": canonical_label,
                        "display_name": entry["name"],
                        "exec": entry["exec"],
                        "terminal": entry["terminal"],
                        "desktop_file": entry["desktop_file"],
                    }
                    break

    # Also detect CLI-only Ollama if installed in PATH
    ollama_bin = shutil.which("ollama")
    if ollama_bin and "Ollama CLI" not in found_by_label:
        found_by_label["Ollama CLI"] = {
            "label": "Ollama CLI",
            "display_name": "Ollama (Terminal)",
            "exec": f"{ollama_bin} list",
            "terminal": "true",
            "desktop_file": "",
        }

    return list(found_by_label.values())


def launch_web_ai(url: str) -> tuple[bool, str]:
    """Open a Web AI assistant URL in the user's default browser."""
    try:
        webbrowser.open(url, new=2)
        return True, f"Opened {url}"
    except OSError as exc:
        return False, f"Could not open browser: {exc}"


def launch_local_ai(app: dict[str, str]) -> tuple[bool, str]:
    """Launch a detected local AI application cleanly without blocking the GUI."""
    exec_str = app.get("exec", "").strip()
    if not exec_str:
        return False, "No launch command found for this application."

    is_terminal = app.get("terminal") == "true"
    try:
        if is_terminal:
            term = shutil.which("x-terminal-emulator") or shutil.which("gnome-terminal") or shutil.which("konsole")
            if term:
                subprocess.Popen(
                    [term, "-e", "bash", "-c", f"{exec_str}; read -p 'Press Enter to close...'"],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True, f"Launched {app['display_name']} in terminal."

        args = shlex.split(exec_str)
        subprocess.Popen(
            args,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True, f"Launched {app['display_name']}."
    except (OSError, ValueError) as exc:
        return False, f"Failed to launch {app.get('display_name', 'app')}: {exc}"
