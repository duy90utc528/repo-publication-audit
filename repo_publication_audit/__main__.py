"""CLI for Repo Publication Audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import audit


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a repository before making it public.")
    parser.add_argument("path", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--format", choices=("text", "json"), default="text")
    arguments = parser.parse_args()
    findings = audit(arguments.path)
    if arguments.format == "json":
        print(json.dumps([finding.as_dict() for finding in findings], indent=2))
    else:
        for finding in findings:
            print(f"{finding.severity.upper():7} {finding.path}: {finding.message}")
        print(f"{len(findings)} finding(s)")
    return 1 if any(finding.severity == "high" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
