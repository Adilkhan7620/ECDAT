"""Unit tests for OpenSSL x509 and s_client parsing."""

import unittest
from pathlib import Path

from shared.models import FindingCategory, FindingSource, ToolName
from scanner.scanners.openssl.parser import OpenSSLParser


class OpenSSLParserTests(unittest.TestCase):
    """Verify OpenSSL text outputs are converted into ECDAT Finding certificate records."""

    def test_parses_rsa_x509_certificate(self) -> None:
        """RSA X.509 certificate text is converted to a Finding with RSA algorithm and key size."""
        x509_text = (
            "Certificate:\n"
            "    Data:\n"
            "        Version: 3 (0x2)\n"
            "        Serial Number:\n"
            "            03:a1:8f:92\n"
            "        Signature Algorithm: sha256WithRSAEncryption\n"
            "        Issuer: C = US, O = Let's Encrypt, CN = R3\n"
            "        Validity\n"
            "            Not Before: Sep  1 00:00:00 2026 GMT\n"
            "            Not After : Nov 30 23:59:59 2026 GMT\n"
            "        Subject: CN = example.com\n"
            "        Subject Public Key Info:\n"
            "            Public Key Algorithm: rsaEncryption\n"
            "                Public-Key: (2048 bit)\n"
            "                Modulus:\n"
            "                    00:c3:...\n"
            "                Exponent: 65537 (0x10001)\n"
            "        X509v3 extensions:\n"
            "            X509v3 Subject Alternative Name:\n"
            "                DNS:example.com, DNS:www.example.com\n"
        )

        finding = OpenSSLParser().parse_x509(x509_text, "cert.pem")
        self.assertIsNotNone(finding)
        assert finding is not None

        self.assertEqual(finding.tool, ToolName.OPENSSL)
        self.assertEqual(finding.category, FindingCategory.CERTIFICATE)
        self.assertEqual(finding.source, FindingSource.CERTIFICATE_FILE)
        self.assertEqual(finding.algorithm, "RSA")
        self.assertEqual(finding.key_size, 2048)
        self.assertEqual(finding.file, "cert.pem")
        self.assertEqual(finding.metadata["subject"], "CN = example.com")
        self.assertEqual(finding.metadata["issuer"], "C = US, O = Let's Encrypt, CN = R3")
        self.assertEqual(finding.metadata["signature_algorithm"], "sha256WithRSAEncryption")

    def test_parses_ecdsa_x509_certificate(self) -> None:
        """ECDSA X.509 certificate text is converted to a Finding with ECDSA algorithm and key size."""
        x509_text = (
            "Certificate:\n"
            "    Data:\n"
            "        Version: 3 (0x2)\n"
            "        Signature Algorithm: ecdsa-with-SHA256\n"
            "        Issuer: CN = ECDAT EC CA\n"
            "        Subject: CN = ec.example.com\n"
            "        Subject Public Key Info:\n"
            "            Public Key Algorithm: id-ecPublicKey\n"
            "                Public-Key: (256 bit)\n"
            "                pub:\n"
            "                    04:4f:...\n"
            "                ASN1 OID: prime256v1\n"
            "                NIST CURVE: P-256\n"
        )

        finding = OpenSSLParser().parse_x509(x509_text, "ec_cert.pem")
        self.assertIsNotNone(finding)
        assert finding is not None

        self.assertEqual(finding.algorithm, "ECDSA")
        self.assertEqual(finding.key_size, 256)

    def test_parses_sclient_tls_output(self) -> None:
        """s_client output extracts TLS version, cipher, subject, and issuer."""
        sclient_text = (
            "CONNECTED(00000003)\n"
            "---\n"
            "Server certificate\n"
            "subject=CN = secure.local\n"
            "issuer=CN = Local Authority\n"
            "---\n"
            "SSL-Session:\n"
            "    Protocol  : TLSv1.3\n"
            "    Cipher    : TLS_AES_256_GCM_SHA384\n"
        )

        findings = OpenSSLParser().parse_sclient(sclient_text, "secure.local:443")
        self.assertEqual(len(findings), 1)

        finding = findings[0]
        self.assertEqual(finding.tool, ToolName.OPENSSL)
        self.assertEqual(finding.category, FindingCategory.CERTIFICATE)
        self.assertEqual(finding.source, FindingSource.CONFIGURATION)
        self.assertEqual(finding.metadata["protocol"], "TLSv1.3")
        self.assertEqual(finding.metadata["cipher"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(finding.metadata["subject"], "CN = secure.local")

    def test_handles_empty_or_invalid_inputs(self) -> None:
        """Empty string or unparseable text returns None / empty tuple without crashing."""
        parser = OpenSSLParser()
        self.assertIsNone(parser.parse_x509("", "cert.pem"))
        self.assertIsNone(parser.parse_x509("invalid text", "cert.pem"))
        self.assertEqual(parser.parse_sclient("", "endpoint:443"), ())
