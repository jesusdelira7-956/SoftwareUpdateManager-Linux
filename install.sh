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
echo "  Installing Linux / Zorin Software Update Manager (v1.0.0)"
echo "=================================================================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required. Install it with: sudo apt install python3"
    exit 1
fi

# Check for Tkinter (required for GUI mode; CLI works without it)
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
    echo ""
    echo "[Notice] python3-tk is not currently installed (needed for Desktop GUI mode)."
    if command -v apt >/dev/null 2>&1; then
        read -r -p "Install python3-tk now via apt? [Y/n]: " ans
        if [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]; then
            sudo apt update && sudo apt install -y python3-tk
        else
            echo "Skipping python3-tk. You can still use --cli and --headless modes."
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
Exec=x-terminal-emulator -e python3 ${INSTALL_DIR}/update_manager.py --cli

[Desktop Action AuditNetwork]
Name=Audit Listening Network Ports
Exec=x-terminal-emulator -e bash -c "python3 ${INSTALL_DIR}/update_manager.py --audit-network; read -p 'Press Enter to close...'"
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
