"""Optional integration test for a locally installed Syft executable."""

import tempfile
import unittest
from pathlib import Path

from scanner.models import ScannerStatus
from scanner.normalizer import FindingNormalizer
from scanner.scanners.syft.scanner import SyftScanner


@unittest.skipUnless(SyftScanner().is_available(), "Syft is not installed")
class SyftIntegrationTests(unittest.TestCase):
    """Run Syft against a local directory fixture when available."""

    def test_detects_components_in_local_fixture(self) -> None:
        """Syft detects software packages in a local application directory."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "requirements.txt").write_text("cryptography==41.0.0\n", encoding="utf-8")
            result = SyftScanner(timeout_seconds=30).scan(target)

        self.assertEqual(result.status, ScannerStatus.COMPLETED)

        normalized = FindingNormalizer().normalize(result.findings)
        if normalized:
            finding = normalized[0]
            self.assertEqual(finding.scanner, "syft")
            self.assertEqual(finding.category, "component")
            self.assertEqual(finding.source, "dependency")
