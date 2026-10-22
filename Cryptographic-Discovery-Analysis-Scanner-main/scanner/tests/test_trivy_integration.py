"""Optional integration test for a locally installed Trivy executable."""

import tempfile
import unittest
from pathlib import Path

from scanner.models import ScannerStatus
from scanner.normalizer import FindingNormalizer
from scanner.scanners.trivy.scanner import TrivyScanner


@unittest.skipUnless(TrivyScanner().is_available(), "Trivy is not installed")
class TrivyIntegrationTests(unittest.TestCase):
    """Run Trivy against a local directory fixture when available."""

    def test_detects_vulnerabilities_in_local_fixture(self) -> None:
        """Trivy detects package vulnerabilities in a local application directory."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "requirements.txt").write_text("pycryptodome==3.18.0\n", encoding="utf-8")
            result = TrivyScanner(timeout_seconds=30).scan(target)

        self.assertEqual(result.status, ScannerStatus.COMPLETED)

        normalized = FindingNormalizer().normalize(result.findings)
        if normalized:
            finding = normalized[0]
            self.assertEqual(finding.scanner, "trivy")
            self.assertEqual(finding.category, "vulnerability")
            self.assertEqual(finding.source, "dependency")
