"""Pre-Update Security & Trust Gate and IPI Output Sanitizer for Linux.

100% Python Standard Library.
- Evaluates package names, paths, and publishers against pup_blocklist.json.
- Computes SHA-256 digests for downloaded binaries/AppImages.
- Sanitizes untrusted package descriptions/metadata against Indirect Prompt
  Injection (IPI) before exposing data through the Stdio MCP Bridge.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BLOCKLIST_FILE = PROJECT_ROOT / "pup_blocklist.json"

_IPI_PATTERNS = (
    re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions"),
    re.compile(r"(?i)system\s*prompt"),
    re.compile(r"(?i)you\s+are\s+now\s+in\s+developer\s+mode"),
    re.compile(r"(?i)<\s*/?(system|assistant|user|instruction)\s*>"),
)


def load_blocklist() -> dict[str, Any]:
    """Load the community PUP blocklist JSON."""
    if BLOCKLIST_FILE.exists():
        try:
            return json.loads(BLOCKLIST_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "blocked_publishers": [],
        "blocked_name_patterns": [],
        "blocked_package_names": [],
        "high_risk_paths": ["/tmp/", "/dev/shm/"],
    }


def evaluate_package_trust(
    name: str,
    pkg_id: str = "",
    install_path: str = "",
    publisher: str = "",
) -> dict[str, Any]:
    """Evaluate a package/binary against the Pre-Update Trust Gate.

    Returns {"status": "TRUSTED"|"WARNING"|"BLOCKED", "reasons": [str]}.
    """
    bl = load_blocklist()
    reasons: list[str] = []
    status = "TRUSTED"

    name_lower = (name or "").lower()
    id_lower = (pkg_id or "").lower()
    pub_lower = (publisher or "").lower()
    path_lower = (install_path or "").lower()

    for blocked_pkg in bl.get("blocked_package_names", []):
        if blocked_pkg.lower() in (name_lower, id_lower):
            status = "BLOCKED"
            reasons.append(f"Matched blocked package ID: {blocked_pkg}")

    for pattern in bl.get("blocked_name_patterns", []):
        if pattern.lower() in name_lower or pattern.lower() in id_lower:
            status = "BLOCKED"
            reasons.append(f"Matched PUP name pattern: {pattern}")

    for pub in bl.get("blocked_publishers", []):
        if pub_lower and pub.lower() in pub_lower:
            status = "BLOCKED"
            reasons.append(f"Blocked publisher: {pub}")

    if status != "BLOCKED" and path_lower:
        for risky in bl.get("high_risk_paths", []):
            if risky.lower() in path_lower:
                status = "WARNING"
                reasons.append(f"Executable resides in high-risk temporary path: {risky}")

    return {"status": status, "reasons": reasons}


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file using 64KB streaming chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


def sanitize_for_ai(text: str, max_length: int = 4000) -> str:
    """Strip potential Indirect Prompt Injection (IPI) payloads from system output."""
    cleaned = text[:max_length]
    for pattern in _IPI_PATTERNS:
        cleaned = pattern.sub("[REDACTED_IPI_PATTERN]", cleaned)
    return cleaned
