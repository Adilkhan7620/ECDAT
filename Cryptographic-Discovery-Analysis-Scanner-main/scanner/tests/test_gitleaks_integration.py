"""Optional integration test for a locally installed Gitleaks executable."""

import tempfile
import unittest
from pathlib import Path

from scanner.models import ScannerStatus
from scanner.normalizer import FindingNormalizer
from scanner.scanners.gitleaks.scanner import GitleaksScanner


@unittest.skipUnless(GitleaksScanner().is_available(), "Gitleaks is not installed")
class GitleaksIntegrationTests(unittest.TestCase):
    """Run Gitleaks against a safe synthetic test fixture when available."""

    def test_detects_secret_in_local_fixture_and_redacts_content(self) -> None:
        """Gitleaks detects dummy test credential without leaking raw secrets."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            # Create a safe test file containing ONLY a dummy synthetic secret pattern
            (target / "dummy_credentials.env").write_text(
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                encoding="utf-8",
            )
            result = GitleaksScanner(timeout_seconds=30).scan(target)

        self.assertEqual(result.status, ScannerStatus.COMPLETED)

        # Normalize findings through the ECDAT normalizer
        normalized = FindingNormalizer().normalize(result.findings)

        # Verify pipeline contract
        if normalized:
            finding = normalized[0]
            self.assertEqual(finding.scanner, "gitleaks")
            self.assertEqual(finding.category, "secret")
            # Verify secrets are redacted in evidence
            self.assertEqual(finding.evidence.original.get("Secret"), "[REDACTED]")
            self.assertNotIn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", str(finding.to_dict()))
