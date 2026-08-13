import tempfile
import unittest
from pathlib import Path

from repo_publication_audit.audit import audit


class AuditTests(unittest.TestCase):
    def create_community_files(self, root: Path) -> None:
        for name in ("README.md", "LICENSE", "CONTRIBUTING.md", "SECURITY.md"):
            (root / name).write_text("ok", encoding="utf-8")

    def test_detects_token_shaped_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.create_community_files(root)
            token = "ghp_" + "abcdefghijklmnopqrstuvwx"
            (root / "config.py").write_text(f"token = '{token}'", encoding="utf-8")
            findings = audit(root)
        self.assertTrue(any(finding.severity == "high" and "GitHub" in finding.message for finding in findings))

    def test_reports_missing_community_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            findings = audit(Path(temporary))
        self.assertEqual({finding.path for finding in findings}, {"README", "LICENSE", "CONTRIBUTING.md", "SECURITY.md"})

    def test_skips_git_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.create_community_files(root)
            (root / ".git").mkdir()
            token = "ghp_" + "abcdefghijklmnopqrstuvwx"
            (root / ".git" / "config").write_text(token, encoding="utf-8")
            findings = audit(root)
        self.assertFalse(any(finding.severity == "high" for finding in findings))

    def test_excludes_relative_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.create_community_files(root)
            private = root / "examples"
            private.mkdir()
            token = "ghp_" + "abcdefghijklmnopqrstuvwx"
            (private / "sanitized-fixture.txt").write_text(token, encoding="utf-8")
            findings = audit(root, excludes=("examples",))
        self.assertFalse(any(finding.severity == "high" for finding in findings))
