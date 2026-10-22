"""Unit tests for safe Gitleaks process execution and structured outcomes."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.models import ScannerStatus
from scanner.scanners.gitleaks.scanner import GitleaksScanner


class GitleaksScannerTests(unittest.TestCase):
    """Verify Gitleaks process execution and result structure."""

    @patch.dict("os.environ", {}, clear=True)
    def test_build_command_uses_json_and_no_shell(self) -> None:
        """The adapter builds an argv list with detect, json report format, and no-git."""
        scanner = GitleaksScanner(timeout_seconds=15)
        command = scanner.build_command(Path("repository with spaces"))

        self.assertIsInstance(command, list)
        self.assertEqual(command[0], "gitleaks")
        self.assertEqual(command[1], "detect")
        self.assertIn("--source", command)
        self.assertIn("--report-format", command)
        self.assertIn("json", command)
        self.assertIn("--no-git", command)
        self.assertEqual(command[3], "repository with spaces")

    def test_executable_resolution_via_env_var_and_constructor(self) -> None:
        """GitleaksScanner checks custom constructor param, env vars, and default name."""
        with patch.dict("os.environ", {"GITLEAKS_PATH": "/custom/path/gitleaks"}):
            self.assertEqual(GitleaksScanner().executable, "/custom/path/gitleaks")

        scanner_override = GitleaksScanner(executable="/override/path/gitleaks")
        self.assertEqual(scanner_override.executable, "/override/path/gitleaks")

    @patch.object(GitleaksScanner, "is_available", return_value=True)
    @patch("scanner.scanners.gitleaks.scanner.subprocess.run")
    def test_scan_captures_raw_json_stderr_and_normalized_findings(self, mock_run, _mock_available) -> None:
        """Mocked Gitleaks JSON output is parsed into findings and sensitive values are redacted."""
        raw_json = json.dumps(
            [
                {
                    "Description": "RSA Private Key",
                    "File": "keys/rsa_key.pem",
                    "StartLine": 5,
                    "RuleID": "rsa-private-key",
                    "Secret": "DUMMY_SECRET_KEY_12345",
                    "Match": "BEGIN RSA PRIVATE KEY",
                    "Fingerprint": "keys/rsa_key.pem:rsa-private-key:5",
                }
            ]
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["gitleaks"], returncode=0, stdout=raw_json, stderr="gitleaks log"
        )
        scanner = GitleaksScanner(timeout_seconds=10)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.COMPLETED)
        self.assertNotIn("DUMMY_SECRET_KEY_12345", result.raw_output)
        self.assertIn("[REDACTED]", result.raw_output)
        self.assertIn("rsa-private-key", result.raw_output)
        self.assertIn("keys/rsa_key.pem", result.raw_output)
        self.assertEqual(result.stderr, "gitleaks log")
        self.assertEqual(len(result.findings), 1)

        finding = result.findings[0]
        self.assertEqual(finding.rule, "rsa-private-key")
        self.assertEqual(finding.file, "keys/rsa_key.pem")
        self.assertEqual(finding.line, 5)

        # Ensure raw secret value is NOT exposed in finding evidence or serialized finding
        self.assertEqual(finding.evidence.original["Secret"], "[REDACTED]")
        self.assertEqual(finding.evidence.original["Match"], "[REDACTED]")
        self.assertNotIn("DUMMY_SECRET_KEY_12345", json.dumps(finding.to_dict()))
        self.assertNotIn("DUMMY_SECRET_KEY_12345", json.dumps(result.to_dict()))

    @patch.object(GitleaksScanner, "is_available", return_value=True)
    @patch("scanner.scanners.gitleaks.scanner.subprocess.run")
    def test_handles_gitleaks_exit_code_1_as_completed(self, mock_run, _mock_available) -> None:
        """Exit code 1 (leaks found) is treated as a completed scan."""
        raw_json = json.dumps([])
        mock_run.return_value = subprocess.CompletedProcess(
            args=["gitleaks"], returncode=1, stdout=raw_json, stderr=""
        )

        with tempfile.TemporaryDirectory() as directory:
            result = GitleaksScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.COMPLETED)

    @patch.object(GitleaksScanner, "is_available", return_value=True)
    @patch("scanner.scanners.gitleaks.scanner.subprocess.run")
    def test_timeout_preserves_any_captured_streams(self, mock_run, _mock_available) -> None:
        """Timeouts return a controlled failure without raising to callers."""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["gitleaks"], timeout=1, output=b"partial output", stderr=b"partial error"
        )
        scanner = GitleaksScanner(timeout_seconds=1)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.raw_output, "partial output")
        self.assertEqual(result.stderr, "partial error")

    @patch.object(GitleaksScanner, "is_available", return_value=False)
    def test_unavailable_gitleaks_returns_controlled_status(self, _mock_available) -> None:
        """A missing executable returns TOOL_UNAVAILABLE."""
        with tempfile.TemporaryDirectory() as directory:
            result = GitleaksScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.TOOL_UNAVAILABLE)

    @patch.object(GitleaksScanner, "is_available", return_value=True)
    @patch("scanner.scanners.gitleaks.scanner.subprocess.run")
    def test_process_error_returns_failed_status(self, mock_run, _mock_available) -> None:
        """Non-zero exit codes other than 0/1 return FAILED status."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["gitleaks"], returncode=2, stdout="", stderr="invalid flag"
        )

        with tempfile.TemporaryDirectory() as directory:
            result = GitleaksScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.exit_code, 2)
