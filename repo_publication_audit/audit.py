"""Filesystem-only audit logic; it never reads ignored large dependency trees."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import fnmatch
from pathlib import Path
import re
import subprocess

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
    rule_id: str
    line: int | None = None

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def audit(root: Path, excludes: tuple[str, ...] = (), respect_gitignore: bool = False) -> list[Finding]:
    """Return publication findings for *root* without network access."""
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    ignored = _gitignore_patterns(root) if respect_gitignore else ()
    findings = _community_findings(root)
    for item in root.rglob("*"):
        if any(part in SKIP_DIRECTORIES for part in item.relative_to(root).parts):
            continue
        if not item.is_file():
            continue
        relative = item.relative_to(root).as_posix()
        if _is_excluded(relative, excludes) or _is_git_ignored(root, relative, ignored):
            continue
        if item.name in SENSITIVE_NAMES or item.suffix in {".pem", ".p12", ".key"}:
            findings.append(Finding("high", relative, "sensitive credential-like file name", "RPA001"))
        if item.stat().st_size > 1_048_576 or item.suffix.lower() in {".png", ".jpg", ".zip", ".pdf"}:
            continue
        try:
            content = item.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in TOKEN_PATTERNS.items():
            if pattern.search(content):
                findings.append(Finding("high", relative, f"possible {label}", "RPA002", _match_line(content, pattern)))
    return findings


def _is_excluded(relative: str, excludes: tuple[str, ...]) -> bool:
    return any(relative == excluded or relative.startswith(f"{excluded.rstrip('/')}/") for excluded in excludes)


def _gitignore_patterns(root: Path) -> tuple[str, ...]:
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return ()
    return tuple(
        line.strip().lstrip("/")
        for line in gitignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and not line.lstrip().startswith("!")
    )


def _is_ignored(relative: str, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatch(relative, pattern.rstrip("/"))
        or relative.startswith(f"{pattern.rstrip('/')}/")
        for pattern in patterns
    )


def _is_git_ignored(root: Path, relative: str, fallback_patterns: tuple[str, ...]) -> bool:
    """Use Git's matcher when possible, retaining a small no-Git fallback."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--no-index", "-q", "--", relative],
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _is_ignored(relative, fallback_patterns)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return _is_ignored(relative, fallback_patterns)


def _match_line(content: str, pattern: re.Pattern[str]) -> int:
    return content[: pattern.search(content).start()].count("\n") + 1


def _community_findings(root: Path) -> list[Finding]:
    names = {item.name.upper() for item in root.iterdir()}
    findings: list[Finding] = []
    for label, filename in COMMUNITY_FILES.items():
        expected = filename.upper()
        if not any(name == expected or name.startswith(f"{expected}.") for name in names):
            findings.append(Finding("medium", filename, f"missing {label} community file", "RPA101"))
    return findings
