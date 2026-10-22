"""Unit tests for safe OpenSSL process execution and structured outcomes."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.models import ScannerStatus
from scanner.scanners.openssl.scanner import OpenSSLScanner


class OpenSSLScannerTests(unittest.TestCase):
    """Verify OpenSSL process execution, endpoint validation, and result structure."""

    def test_endpoint_validation_accepts_valid_host_port(self) -> None:
        """validate_endpoint parses host and port and rejects flags or malformed strings."""
        self.assertEqual(OpenSSLScanner.validate_endpoint("example.com:443"), ("example.com", 443))
        self.assertEqual(OpenSSLScanner.validate_endpoint("localhost:8443"), ("localhost", 8443))
        self.assertEqual(OpenSSLScanner.validate_endpoint("127.0.0.1:4433"), ("127.0.0.1", 4433))

        # Reject flags, invalid ports, and malformed strings
        self.assertIsNone(OpenSSLScanner.validate_endpoint("-connect"))
        self.assertIsNone(OpenSSLScanner.validate_endpoint("--option"))
        self.assertIsNone(OpenSSLScanner.validate_endpoint("example.com"))
        self.assertIsNone(OpenSSLScanner.validate_endpoint("example.com:99999"))
        self.assertIsNone(OpenSSLScanner.validate_endpoint("example.com:0"))

    def test_executable_resolution_via_env_var_and_constructor(self) -> None:
        """OpenSSLScanner checks custom constructor param, env vars, and default name."""
        with patch.dict("os.environ", {"OPENSSL_PATH": "/custom/path/openssl"}):
            self.assertEqual(OpenSSLScanner().executable, "/custom/path/openssl")

        scanner_override = OpenSSLScanner(executable="/override/path/openssl")
        self.assertEqual(scanner_override.executable, "/override/path/openssl")

    @patch.object(OpenSSLScanner, "is_available", return_value=True)
    @patch("scanner.scanners.openssl.scanner.subprocess.run")
    def test_scan_endpoint_captures_tls_details(self, mock_run, _mock_available) -> None:
        """Mocked s_client output is parsed into TLS certificate findings."""
        sclient_stdout = (
            "CONNECTED(00000003)\n"
            "---\n"
            "Certificate chain\n"
            " 0 s:CN = localhost\n"
            "   i:CN = ECDAT Test CA\n"
            "---\n"
            "Server certificate\n"
            "subject=CN = localhost\n"
            "issuer=CN = ECDAT Test CA\n"
            "---\n"
            "SSL-Session:\n"
            "    Protocol  : TLSv1.3\n"
            "    Cipher    : TLS_AES_256_GCM_SHA384\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["openssl", "s_client"], returncode=0, stdout=sclient_stdout, stderr=""
        )

        result = OpenSSLScanner(timeout_seconds=10).scan(Path("localhost:443"))

        self.assertEqual(result.status, ScannerStatus.COMPLETED)
        self.assertEqual(len(result.findings), 1)

        finding = result.findings[0]
        self.assertEqual(finding.tool, "openssl")
        self.assertEqual(finding.category, "certificate")
        self.assertEqual(finding.source, "configuration")
        self.assertEqual(finding.metadata["protocol"], "TLSv1.3")
        self.assertEqual(finding.metadata["cipher"], "TLS_AES_256_GCM_SHA384")

    @patch.object(OpenSSLScanner, "is_available", return_value=True)
    @patch("scanner.scanners.openssl.scanner.subprocess.run")
    def test_timeout_preserves_any_captured_streams(self, mock_run, _mock_available) -> None:
        """Timeouts return a controlled failure without raising to callers."""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["openssl"], timeout=1, output=b"partial output", stderr=b"partial error"
        )
        scanner = OpenSSLScanner(timeout_seconds=1)

        result = scanner.scan(Path("example.com:443"))

        self.assertEqual(result.status, ScannerStatus.FAILED)
        self.assertEqual(result.raw_output, "partial output")
        self.assertEqual(result.stderr, "partial error")

    @patch.object(OpenSSLScanner, "is_available", return_value=False)
    def test_unavailable_openssl_returns_controlled_status(self, _mock_available) -> None:
        """A missing executable returns TOOL_UNAVAILABLE."""
        with tempfile.TemporaryDirectory() as directory:
            result = OpenSSLScanner().scan(Path(directory))

        self.assertEqual(result.status, ScannerStatus.TOOL_UNAVAILABLE)
