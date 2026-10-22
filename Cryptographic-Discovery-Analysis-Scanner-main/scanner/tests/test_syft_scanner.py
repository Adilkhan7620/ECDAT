"""Unit tests for safe Syft process execution and structured outcomes."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.models import ScannerStatus
from scanner.scanners.syft.scanner import SyftScanner


class SyftScannerTests(unittest.TestCase):
    """Verify Syft process execution and result structure."""

    @patch.dict("os.environ", {}, clear=True)
    def test_build_command_uses_json_and_no_shell(self) -> None:
        """The adapter builds an argv list with target directory and json output."""
        scanner = SyftScanner(timeout_seconds=15)
        command = scanner.build_command(Path("repository with spaces"))

        self.assertIsInstance(command, list)
        self.assertEqual(command[0], "syft")
        self.assertEqual(command[1], "dir:repository with spaces")
        self.assertIn("-o", command)
        self.assertIn("json", command)

    def test_executable_resolution_via_env_var_and_constructor(self) -> None:
        """SyftScanner checks custom constructor param, env vars, and default name."""
        with patch.dict("os.environ", {"SYFT_PATH": "/custom/path/syft"}):
            self.assertEqual(SyftScanner().executable, "/custom/path/syft")

        scanner_override = SyftScanner(executable="/override/path/syft")
        self.assertEqual(scanner_override.executable, "/override/path/syft")

    @patch.object(SyftScanner, "is_available", return_value=True)
    @patch("scanner.scanners.syft.scanner.subprocess.run")
    def test_scan_captures_raw_json_stderr_and_normalized_findings(self, mock_run, _mock_available) -> None:
        """Mocked Syft JSON output is parsed into component findings."""
        raw_json = json.dumps(
            {
                "artifacts": [
                    {
                        "name": "pycryptodome",
                        "version": "3.18.0",
                        "type": "python",
                        "purl": "pkg:pypi/pycryptodome@3.18.0",
                        "locations": [{"path": "requirements.txt"}],
                    }
                ]
            }
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["syft"], returncode=0, stdout=raw_json, stderr="syft log"
        )
        scanner = SyftScanner(timeout_seconds=10)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.COMPLETED)
        self.assertEqual(result.raw_output, raw_json)
        self.assertEqual(result.stderr, "syft log")
        self.assertEqual(len(result.findings), 1)

        finding = result.findings[0]
        self.assertEqual(finding.tool, "syft")
        self.assertEqual(finding.category, "component")
        self.assertEqual(finding.source, "dependency")
        self.assertEqual(finding.file, "requirements.txt")
        self.assertEqual(finding.metadata["name"], "pycryptodome")
        self.assertEqual(finding.metadata["version"], "3.18.0")
        self.assertEqual(finding.metadata["purl"], "pkg:pypi/pycryptodome@3.18.0")

    @patch.object(SyftScanner, "is_available", return_value=True)
    @patch("scanner.scanners.syft.scanner.subprocess.run")
    def test_timeout_preserves_any_captured_streams(self, mock_run, _mock_available) -> None:
        """Timeouts return a controlled failure without raising to callers."""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["syft"], timeout=1, output=b"partial output", stderr=b"partial error"
        )
        scanner = SyftScanner(timeout_seconds=1)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.raw_output, "partial output")
        self.assertEqual(result.stderr, "partial error")

    @patch.object(SyftScanner, "is_available", return_value=False)
    def test_unavailable_syft_returns_controlled_status(self, _mock_available) -> None:
        """A missing executable returns TOOL_UNAVAILABLE."""
        with tempfile.TemporaryDirectory() as directory:
            result = SyftScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.TOOL_UNAVAILABLE)

    @patch.object(SyftScanner, "is_available", return_value=True)
    @patch("scanner.scanners.syft.scanner.subprocess.run")
    def test_process_error_returns_failed_status(self, mock_run, _mock_available) -> None:
        """Non-zero exit codes return FAILED status."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["syft"], returncode=1, stdout="", stderr="invalid cataloger"
        )

        with tempfile.TemporaryDirectory() as directory:
            result = SyftScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.exit_code, 1)
