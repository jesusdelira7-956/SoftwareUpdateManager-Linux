# Security Policy

## Design Principles
1. **Least-Privilege Execution:** The GUI and CLI always run as the unprivileged desktop user. Only privileged OS operations (`apt`, `dpkg`, `snap`, `ufw`, `timeshift`) elevate via `pkexec` or `sudo`.
2. **Zero Third-Party Python Dependencies:** 100% Python Standard Library eliminates external PyPI supply-chain exposure.
3. **Zero Open Ports:** The MCP Agent Bridge uses strictly `stdin`/`stdout` JSON-RPC 2.0.
4. **Pre-Update Trust Gate:** All packages are screened against `pup_blocklist.json`, and downloaded archives/AppImages have SHA-256 checksums computed and logged before execution.

## Reporting a Vulnerability
Please open a private security advisory on the project's GitHub repository rather than posting exploit details publicly.

## Privacy & Anti-Solicitation Policy
> **Notice:** Automated repository scraping, third-party "trust index" badge-farming, contact email harvesting, and unsolicited commercial outreach regarding this repository are strictly unwelcome. All legitimate security disclosures, questions, and collaboration must be submitted exclusively through **GitHub Issues** or **GitHub Security Advisories**. Please respect developer privacy.
