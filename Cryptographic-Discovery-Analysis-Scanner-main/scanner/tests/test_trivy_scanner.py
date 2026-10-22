"""Unit tests for safe Trivy process execution and structured outcomes."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.models import ScannerStatus
from scanner.scanners.trivy.scanner import TrivyScanner


class TrivyScannerTests(unittest.TestCase):
    """Verify Trivy process execution and result structure."""

    @patch.dict("os.environ", {}, clear=True)
    def test_build_command_uses_json_and_no_shell(self) -> None:
        """The adapter builds an argv list with fs, json format, and target path."""
        scanner = TrivyScanner(timeout_seconds=15)
        command = scanner.build_command(Path("repository with spaces"))

        self.assertIsInstance(command, list)
        self.assertEqual(command[0], "trivy")
        self.assertEqual(command[1], "fs")
        self.assertIn("--format", command)
        self.assertIn("json", command)
        self.assertEqual(command[4], "repository with spaces")

    def test_executable_resolution_via_env_var_and_constructor(self) -> None:
        """TrivyScanner checks custom constructor param, env vars, and default name."""
        with patch.dict("os.environ", {"TRIVY_PATH": "/custom/path/trivy"}):
            self.assertEqual(TrivyScanner().executable, "/custom/path/trivy")

        scanner_override = TrivyScanner(executable="/override/path/trivy")
        self.assertEqual(scanner_override.executable, "/override/path/trivy")

    @patch.object(TrivyScanner, "is_available", return_value=True)
    @patch("scanner.scanners.trivy.scanner.subprocess.run")
    def test_scan_captures_raw_json_stderr_and_normalized_findings(self, mock_run, _mock_available) -> None:
        """Mocked Trivy JSON output is parsed into vulnerability findings."""
        raw_json = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Class": "lang-pkgs",
                        "Type": "pip",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-49460",
                                "PkgName": "pycryptodome",
                                "InstalledVersion": "3.18.0",
                                "FixedVersion": "3.19.0",
                                "Severity": "HIGH",
                                "Title": "Side-channel vulnerability in PyCryptodome",
                                "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-49460",
                            }
                        ],
                    }
                ],
            }
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["trivy"], returncode=0, stdout=raw_json, stderr="trivy log"
        )
        scanner = TrivyScanner(timeout_seconds=10)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.COMPLETED)
        self.assertEqual(result.raw_output, raw_json)
        self.assertEqual(result.stderr, "trivy log")
        self.assertEqual(len(result.findings), 1)

        finding = result.findings[0]
        self.assertEqual(finding.tool, "trivy")
        self.assertEqual(finding.category, "vulnerability")
        self.assertEqual(finding.source, "dependency")
        self.assertEqual(finding.rule, "CVE-2023-49460")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.file, "requirements.txt")
        self.assertEqual(finding.metadata["vulnerability_id"], "CVE-2023-49460")
        self.assertEqual(finding.metadata["package_name"], "pycryptodome")
        self.assertEqual(finding.metadata["installed_version"], "3.18.0")
        self.assertEqual(finding.metadata["fixed_version"], "3.19.0")

    @patch.object(TrivyScanner, "is_available", return_value=True)
    @patch("scanner.scanners.trivy.scanner.subprocess.run")
    def test_timeout_preserves_any_captured_streams(self, mock_run, _mock_available) -> None:
        """Timeouts return a controlled failure without raising to callers."""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["trivy"], timeout=1, output=b"partial output", stderr=b"partial error"
        )
        scanner = TrivyScanner(timeout_seconds=1)

        with tempfile.TemporaryDirectory() as directory:
            result = scanner.scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.raw_output, "partial output")
        self.assertEqual(result.stderr, "partial error")

    @patch.object(TrivyScanner, "is_available", return_value=False)
    def test_unavailable_trivy_returns_controlled_status(self, _mock_available) -> None:
        """A missing executable returns TOOL_UNAVAILABLE."""
        with tempfile.TemporaryDirectory() as directory:
            result = TrivyScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.TOOL_UNAVAILABLE)

    @patch.object(TrivyScanner, "is_available", return_value=True)
    @patch("scanner.scanners.trivy.scanner.subprocess.run")
    def test_process_error_returns_failed_status(self, mock_run, _mock_available) -> None:
        """Non-zero exit codes return FAILED status."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["trivy"], returncode=1, stdout="", stderr="db download failed"
        )

        with tempfile.TemporaryDirectory() as directory:
            result = TrivyScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.exit_code, 1)
