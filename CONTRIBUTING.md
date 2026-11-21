# Contributing to Linux / Zorin Software Update Manager

Thank you for helping improve this open-source Linux updater and security dashboard!

## Core Engineering Rules
1. **Zero Third-Party `pip` Dependencies:** All Python code must use **100% Python 3.10+ Standard Library** (`tkinter`, `urllib`, `json`, `subprocess`, `concurrent.futures`, etc.).
2. **Least-Privilege Execution:** Never require running the GUI as `root`. Use `core/privilege_helper.py` (`pkexec` / `sudo`) only for system-level operations.
3. **Zero Hardcoded User Paths:** Always use `Path.home()`, XDG environment variables, or `core/config_manager.py`.
4. **Smart Caching First:** Any new provider added to `providers.json` must avoid blind re-downloads by checking release tags, ETags, redirect filenames, or build IDs.

## Adding a New Standalone App / AppImage Provider
1. Edit `providers.json` and add a new entry under `"providers"` using one of the supported strategies (`github_release`, `http_redirect`, `http_etag`, `http_redirect_tar`, `docker_release_notes_deb`).
2. Validate JSON syntax and run:
   ```bash
   python3 -m py_compile update_manager.py agent_bridge.py core/*.py ui/*.py
   python3 update_manager.py --check
   ```
3. Open a Pull Request describing the tested Linux distribution and provider behavior.
