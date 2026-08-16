"""Machine-readable report formats for publication findings."""

from __future__ import annotations

from .audit import Finding


def sarif_report(findings: list[Finding]) -> dict[str, object]:
    """Create a GitHub-compatible SARIF 2.1.0 document."""
    rules = {
        "RPA001": ("Credential-like file", "A file name commonly used for credentials or private keys was found."),
        "RPA002": ("Possible credential", "A token-shaped string was found. Verify it is not a live credential."),
        "RPA101": ("Missing community file", "A standard open-source community document is missing."),
    }
    results: list[dict[str, object]] = []
    used_rules: set[str] = set()
    for finding in findings:
        used_rules.add(finding.rule_id)
        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": "error" if finding.severity == "high" else "warning",
            "message": {"text": finding.message},
        }
        if finding.path and finding.rule_id != "RPA101":
            region = {"startLine": finding.line or 1}
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": region}}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Repo Publication Audit",
                "version": "0.3.0",
                "rules": [
                    {"id": rule_id, "shortDescription": {"text": rules[rule_id][0]}, "fullDescription": {"text": rules[rule_id][1]}}
                    for rule_id in sorted(used_rules)
                ],
            }},
            "results": results,
        }],
    }
