"""CLI for Repo Publication Audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib

from .audit import audit

VERSION = "0.2.0"
SEVERITY_ORDER = {"never": 3, "high": 2, "medium": 1}


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a repository before making it public.")
    parser.add_argument("path", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATH", help="skip a relative path or directory")
    parser.add_argument("--respect-gitignore", action="store_true", help="skip paths matched by the root .gitignore")
    parser.add_argument("--fail-on", choices=("high", "medium", "never"), default=None, help="lowest severity that returns exit code 1")
    parser.add_argument("--config", type=Path, help="read defaults from a TOML file")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    arguments = parser.parse_args()
    settings = _settings(arguments.path, arguments.config)
    excludes = tuple(settings.get("exclude", ())) + tuple(arguments.exclude)
    respect_gitignore = arguments.respect_gitignore or settings.get("respect_gitignore", False)
    fail_on = arguments.fail_on or settings.get("fail_on", "high")
    findings = audit(arguments.path, excludes, respect_gitignore)
    if arguments.format == "json":
        print(json.dumps([finding.as_dict() for finding in findings], indent=2))
    else:
        for finding in findings:
            print(f"{finding.severity.upper():7} {finding.path}: {finding.message}")
        print(f"{len(findings)} finding(s)")
    return 1 if any(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[fail_on] for finding in findings) else 0


def _settings(root: Path, config: Path | None) -> dict[str, object]:
    config_path = config or root / ".repo-publication-audit.toml"
    if not config_path.is_file():
        return {}
    settings = tomllib.loads(config_path.read_text(encoding="utf-8")).get("audit", {})
    if not isinstance(settings, dict):
        raise ValueError("[audit] must be a TOML table")
    if "exclude" in settings and (not isinstance(settings["exclude"], list) or not all(isinstance(item, str) for item in settings["exclude"])):
        raise ValueError("audit.exclude must be an array of strings")
    if "fail_on" in settings and settings["fail_on"] not in SEVERITY_ORDER:
        raise ValueError("audit.fail_on must be high, medium, or never")
    if "respect_gitignore" in settings and not isinstance(settings["respect_gitignore"], bool):
        raise ValueError("audit.respect_gitignore must be a boolean")
    return settings


if __name__ == "__main__":
    raise SystemExit(main())
