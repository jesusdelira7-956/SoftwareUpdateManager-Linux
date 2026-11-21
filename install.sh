#!/usr/bin/env bash
# ==============================================================================
# Linux / Zorin Software Update Manager — 1-Click Installer
# Zero pip dependencies (100% Python Standard Library)
# ==============================================================================
set -euo pipefail

APP_ID="software-update-manager"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/${APP_ID}"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

echo "=================================================================="
echo "  Installing Universal Linux Software Update Manager (v1.1.0)"
echo "=================================================================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required. Install python3 via your distro's package manager."
    exit 1
fi

# Check for Tkinter (required for GUI mode; CLI works without it)
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
    echo ""
    echo "[Notice] Python Tkinter is not currently installed (needed for Desktop GUI mode)."
    TK_CMD=""
    TK_PKG=""
    if command -v apt >/dev/null 2>&1; then
        TK_PKG="python3-tk"
        TK_CMD="sudo apt update && sudo apt install -y python3-tk"
    elif command -v dnf5 >/dev/null 2>&1; then
        TK_PKG="python3-tkinter"
        TK_CMD="sudo dnf5 install -y python3-tkinter"
    elif command -v dnf >/dev/null 2>&1; then
        TK_PKG="python3-tkinter"
        TK_CMD="sudo dnf install -y python3-tkinter"
    elif command -v pacman >/dev/null 2>&1; then
        TK_PKG="tk"
        TK_CMD="sudo pacman -S --noconfirm tk"
    elif command -v zypper >/dev/null 2>&1; then
        TK_PKG="python3-tk"
        TK_CMD="sudo zypper --non-interactive install python3-tk"
    fi

    if [ -n "$TK_CMD" ]; then
        read -r -p "Install ${TK_PKG} now? [Y/n]: " ans
        if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then
            eval "$TK_CMD"
        else
            echo "Skipping ${TK_PKG}. You can still use --cli and --check modes."
        fi
    fi
fi

echo "Staging application files to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR" "$BIN_DIR" "$DESKTOP_DIR"
cp -r "$SCRIPT_DIR/core" "$SCRIPT_DIR/ui" "$SCRIPT_DIR/assets" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/update_manager.py" "$SCRIPT_DIR/agent_bridge.py" \
   "$SCRIPT_DIR/providers.json" "$SCRIPT_DIR/pup_blocklist.json" \
   "$SCRIPT_DIR/agent_permissions.json" "$INSTALL_DIR/"

chmod +x "$INSTALL_DIR/update_manager.py" "$INSTALL_DIR/agent_bridge.py"

# Create CLI symlink in ~/.local/bin
ln -sfn "$INSTALL_DIR/update_manager.py" "$BIN_DIR/$APP_ID"
echo "Installed CLI command: $BIN_DIR/$APP_ID"

# Resolve portable terminal emulator across GNOME, KDE, XFCE, and tiling WMs
TERM_EXEC=""
for candidate in xdg-terminal-exec x-terminal-emulator gnome-terminal konsole xfce4-terminal mate-terminal kitty alacritty xterm; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if [ "$candidate" = "gnome-terminal" ]; then
            TERM_EXEC="gnome-terminal --"
        elif [ "$candidate" = "xdg-terminal-exec" ]; then
            TERM_EXEC="xdg-terminal-exec"
        else
            TERM_EXEC="${candidate} -e"
        fi
        break
    fi
done
TERM_EXEC="${TERM_EXEC:-xterm -e}"

# Create .desktop launcher with both GUI and CLI actions
ICON_PATH="${INSTALL_DIR}/assets/app_icon.png"
if [ ! -f "$ICON_PATH" ]; then
    ICON_PATH="system-software-update"
fi

DESKTOP_FILE="$DESKTOP_DIR/${APP_ID}.desktop"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Software Update Manager
GenericName=Linux Software Updater & Intrusion Shield
Comment=Dual-Mode (GUI + CLI) Software Updater, Network Sentinel, and Zero-Port MCP Bridge
Exec=python3 ${INSTALL_DIR}/update_manager.py --gui
Icon=${ICON_PATH}
Terminal=false
Categories=System;Utility;Settings;
Actions=LaunchCLI;AuditNetwork;

[Desktop Action LaunchCLI]
Name=Launch Interactive CLI Mode
Exec=${TERM_EXEC} python3 ${INSTALL_DIR}/update_manager.py --cli

[Desktop Action AuditNetwork]
Name=Audit Listening Network Ports
Exec=${TERM_EXEC} bash -c "python3 ${INSTALL_DIR}/update_manager.py --audit-network; read -p 'Press Enter to close...'"
EOF
chmod +x "$DESKTOP_FILE"

if [ -d "$HOME/Desktop" ]; then
    cp "$DESKTOP_FILE" "$HOME/Desktop/Software-Update-Manager.desktop"
    chmod +x "$HOME/Desktop/Software-Update-Manager.desktop"
fi

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

echo ""
echo "Installation complete!"
echo "  - GUI Mode:      software-update-manager --gui  (or click Desktop/Menu icon)"
echo "  - CLI Mode:      software-update-manager --cli"
echo "  - Headless Mode: software-update-manager --check"
echo "  - MCP Bridge:    software-update-manager --mcp"
