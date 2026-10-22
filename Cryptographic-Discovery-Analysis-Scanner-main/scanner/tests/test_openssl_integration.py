"""Integration test for OpenSSL certificate and TLS endpoint inspection."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from scanner.models import ScannerStatus
from scanner.normalizer import FindingNormalizer
from scanner.scanners.openssl.scanner import OpenSSLScanner


@unittest.skipUnless(OpenSSLScanner().is_available(), "OpenSSL is not installed")
class OpenSSLIntegrationTests(unittest.TestCase):
    """Run OpenSSL against a local self-signed certificate fixture using native OpenSSL."""

    def test_inspects_local_self_signed_certificate_fixture(self) -> None:
        """OpenSSL generates a local X.509 cert fixture and extracts RSA 2048-bit metadata."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            cert_file = target / "test_cert.pem"
            key_file = target / "test_key.pem"

            # Generate a temporary self-signed certificate using native openssl CLI
            cmd = [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_file),
                "-out",
                str(cert_file),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=ecdat.test.local/O=ECDAT Integration Test",
            ]
            subprocess.run(cmd, check=True, capture_output=True)

            result = OpenSSLScanner(timeout_seconds=30).scan(target)

        self.assertEqual(result.status, ScannerStatus.COMPLETED)

        normalized = FindingNormalizer().normalize(result.findings)
        self.assertTrue(len(normalized) >= 1)

        finding = normalized[0]
        self.assertEqual(finding.scanner, "openssl")
        self.assertEqual(finding.category, "certificate")
        self.assertEqual(finding.algorithm, "RSA")
        self.assertEqual(finding.key_size, 2048)
        self.assertIn("ecdat.test.local", finding.subject or finding.metadata.get("subject", ""))
