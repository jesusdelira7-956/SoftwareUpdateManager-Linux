## Summary of Changes
Provide a brief summary of the changes made, the motivation behind them, and what problems they resolve on Linux.

Fixes #(issue number if applicable)

## Type of Change
- [ ] 🐛 Bug fix (non-breaking change fixing an issue on Linux)
- [ ] ✨ New feature, AppImage provider, or Dev SDK detection
- [ ] 🛡️ Security / Defensive hardening enhancement (IPI / Socket Audit / UFW)
- [ ] ⚡ Performance or UI responsiveness optimization
- [ ] 📝 Documentation update or community standard file
- [ ] 🔧 Build / CI / Packaging script improvement

## Verification & Testing Checklist
- [ ] Tested locally on Zorin OS, Ubuntu, or Debian.
- [ ] Verified that **zero third-party `pip` runtime dependencies** were added (100% Python Standard Library).
- [ ] Verified Python syntax across all modules:
  ```bash
  python3 -m py_compile update_manager.py core/*.py ui/*.py
  ```
- [ ] Verified headless flags (`--check`, `--audit-network`, `--specs`, `--mcp`).
- [ ] Verified that no private paths (`/home/...`) or personal credentials are hardcoded.
- [ ] Relevant documentation or README updated where applicable.
