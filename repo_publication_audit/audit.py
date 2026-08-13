"""Filesystem-only audit logic; it never reads ignored large dependency trees."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re

SKIP_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "__pycache__"}
SENSITIVE_NAMES = {".env", "id_rsa", "credentials.json", "service-account.json"}
COMMUNITY_FILES = {"README": "README", "LICENSE": "LICENSE", "CONTRIBUTING": "CONTRIBUTING.md", "SECURITY": "SECURITY.md"}
TOKEN_PATTERNS = {
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    "OpenAI key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
}


@dataclass(frozen=True)
class Finding:
    severity: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def audit(root: Path) -> list[Finding]:
    """Return publication findings for *root* without network access."""
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    findings = _community_findings(root)
    for item in root.rglob("*"):
        if any(part in SKIP_DIRECTORIES for part in item.relative_to(root).parts):
            continue
        if not item.is_file():
            continue
        relative = item.relative_to(root).as_posix()
        if item.name in SENSITIVE_NAMES or item.suffix in {".pem", ".p12", ".key"}:
            findings.append(Finding("high", relative, "sensitive credential-like file name"))
        if item.stat().st_size > 1_048_576 or item.suffix.lower() in {".png", ".jpg", ".zip", ".pdf"}:
            continue
        try:
            content = item.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in TOKEN_PATTERNS.items():
            if pattern.search(content):
                findings.append(Finding("high", relative, f"possible {label}"))
    return findings


def _community_findings(root: Path) -> list[Finding]:
    names = {item.name.upper() for item in root.iterdir()}
    findings: list[Finding] = []
    for label, filename in COMMUNITY_FILES.items():
        expected = filename.upper()
        if not any(name == expected or name.startswith(f"{expected}.") for name in names):
            findings.append(Finding("medium", filename, f"missing {label} community file"))
    return findings
