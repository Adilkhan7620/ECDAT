"""Tests for independent adapter orchestration."""

import tempfile
import unittest
from pathlib import Path

from scanner.models import ScannerStatus
from scanner.orchestrator import ScanOrchestrator
from scanner.scanners import GitleaksScanner, SemgrepScanner


class ScanOrchestratorTests(unittest.TestCase):
    """Verify selection and input validation behavior."""

    def setUp(self) -> None:
        """Create a small two-scanner registry for each test."""
        self.orchestrator = ScanOrchestrator([SemgrepScanner(), GitleaksScanner()])

    def test_scan_returns_controlled_result_for_each_selected_scanner(self) -> None:
        """No external tool must be installed for a skeleton scan."""
        with tempfile.TemporaryDirectory() as directory:
            results = self.orchestrator.scan(Path(directory))

        self.assertEqual([result.scanner for result in results], ["semgrep", "gitleaks"])
        self.assertTrue(
            all(
                result.status in {ScannerStatus.COMPLETED, ScannerStatus.NOT_IMPLEMENTED, ScannerStatus.TOOL_UNAVAILABLE}
                for result in results
            )
        )

    def test_unknown_scanner_is_rejected(self) -> None:
        """Misspelled scanner names do not silently run a partial scan."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Unknown scanner"):
                self.orchestrator.scan(Path(directory), ["unknown"])

    def test_non_directory_target_is_rejected(self) -> None:
        """The phase-one CLI accepts local directories only."""
        with self.assertRaisesRegex(ValueError, "existing local directory"):
            self.orchestrator.scan(Path("does-not-exist"))
