"""Unit tests for safe Semgrep process execution and structured outcomes."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.models import ScannerStatus
from scanner.scanners.semgrep.scanner import SemgrepScanner


class SemgrepScannerTests(unittest.TestCase):
    """Verify Semgrep never needs a real executable in unit tests."""

    @patch.dict("os.environ", {}, clear=True)
    def test_build_command_uses_json_and_no_shell_interpolation(self) -> None:
        """The adapter builds an argv list containing the local rule file."""
        scanner = SemgrepScanner(timeout_seconds=15)
        command = scanner.build_command(Path("repository with spaces"))

        self.assertIsInstance(command, list)
        self.assertIn("--json", command)
        self.assertIn("--config", command)
        self.assertEqual(command[-1], "repository with spaces")

    def test_executable_resolution_via_env_var_and_constructor(self) -> None:
        """SemgrepScanner checks custom constructor param, env vars, and default name."""
        with patch.dict("os.environ", {"SEMGREP_PATH": "/custom/path/semgrep"}):
            self.assertEqual(SemgrepScanner().executable, "/custom/path/semgrep")

        scanner_override = SemgrepScanner(executable="/override/path/semgrep")
        self.assertEqual(scanner_override.executable, "/override/path/semgrep")


    @patch.object(SemgrepScanner, "is_available", return_value=True)
    @patch("scanner.scanners.semgrep.scanner.subprocess.run")
    def test_scan_captures_raw_json_stderr_and_normalized_findings(self, mock_run, _mock_available) -> None:
        """Mocked Semgrep output is retained separately from normalized results."""
        raw_json = json.dumps(
            {
                "results": [
                    {
                        "check_id": "ecdat.crypto.ecdh",
                        "path": "src/key_exchange.py",
                        "start": {"line": 8},
                        "extra": {
                            "message": "ECDH observed",
                            "severity": "INFO",
                            "language": "python",
                        },
                    }
                ]
            }
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["semgrep"], returncode=0, stdout=raw_json, stderr="native diagnostic"
        )
        scanner = SemgrepScanner(timeout_seconds=9)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.COMPLETED)
        self.assertEqual(result.raw_output, raw_json)
        self.assertEqual(result.stderr, "native diagnostic")
        self.assertEqual(result.findings[0].algorithm, "ECDH")
        self.assertEqual(result.findings[0].metadata["language"], "python")
        self.assertEqual(result.command[0], scanner.executable)
        self.assertFalse(mock_run.call_args.kwargs["shell"])
        self.assertTrue(mock_run.call_args.kwargs["capture_output"])
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 9)

    @patch.object(SemgrepScanner, "is_available", return_value=True)
    @patch("scanner.scanners.semgrep.scanner.subprocess.run")
    def test_timeout_preserves_any_captured_streams(self, mock_run, _mock_available) -> None:
        """Timeouts return a controlled failure without raising to callers."""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["semgrep"], timeout=1, output=b"partial json", stderr=b"partial error"
        )
        scanner = SemgrepScanner(timeout_seconds=1)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.raw_output, "partial json")
        self.assertEqual(result.stderr, "partial error")

    @patch.object(SemgrepScanner, "is_available", return_value=False)
    def test_unavailable_semgrep_returns_controlled_status(self, _mock_available) -> None:
        """A missing executable is expected and does not require installation."""
        with tempfile.TemporaryDirectory() as directory:
            result = SemgrepScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.TOOL_UNAVAILABLE)
