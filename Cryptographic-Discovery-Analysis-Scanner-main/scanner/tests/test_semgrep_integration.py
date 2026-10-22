"""Optional integration test for a locally installed Semgrep executable."""

import shutil
import tempfile
import unittest
from pathlib import Path

from scanner.models import ScannerStatus
from scanner.scanners.semgrep.scanner import SemgrepScanner


@unittest.skipUnless(SemgrepScanner().is_available(), "Semgrep is not installed")
class SemgrepIntegrationTests(unittest.TestCase):
    """Run the local rules only when Semgrep is available in the environment."""

    def test_detects_aes_in_local_python_fixture(self) -> None:
        """The ECDAT rule set produces an AES discovery from a temporary repo."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "crypto_fixture.py").write_text("algorithm = 'AES'\n", encoding="utf-8")
            result = SemgrepScanner(timeout_seconds=30).scan(target)

        self.assertEqual(result.status, ScannerStatus.COMPLETED)
        self.assertTrue(any(finding.algorithm == "AES" for finding in result.findings))
