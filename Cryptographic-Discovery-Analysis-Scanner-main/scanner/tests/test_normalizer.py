"""Comprehensive unit tests for ECDAT Canonical Finding Normalization layer."""

import json
import unittest
from pathlib import Path

from shared.models import Finding, FindingCategory, FindingSource, ToolEvidence, ToolName
from scanner.models import CanonicalFinding, ScannerResult, ScannerStatus
from scanner.normalizer import FindingNormalizer
from scanner.scanners.gitleaks.parser import GitleaksParser
from scanner.scanners.openssl.parser import OpenSSLParser
from scanner.scanners.semgrep.parser import SemgrepParser
from scanner.scanners.syft.parser import SyftParser
from scanner.scanners.trivy.parser import TrivyParser


class CanonicalFindingNormalizerTests(unittest.TestCase):
    """Test normalization of findings across all 5 ECDAT scanners."""

    def test_normalize_semgrep_crypto_finding(self) -> None:
        """Semgrep crypto API finding maps to canonical algorithm, location, evidence, and provenance."""
        semgrep_json = json.dumps(
            {
                "results": [
                    {
                        "check_id": "ecdat.crypto.rsa",
                        "path": "src/crypto_utils.py",
                        "start": {"line": 42},
                        "extra": {
                            "message": "RSA cipher initialization observed",
                            "severity": "WARNING",
                            "language": "python",
                        },
                    }
                ]
            }
        )
        findings = SemgrepParser().parse(semgrep_json, Path("/target"))
        self.assertEqual(len(findings), 1)

        canonical_list = FindingNormalizer().normalize(findings)
        self.assertEqual(len(canonical_list), 1)
        canonical = canonical_list[0]

        self.assertIsInstance(canonical, CanonicalFinding)
        self.assertEqual(canonical.finding_id, findings[0].finding_id)
        self.assertEqual(canonical.scanner, ToolName.SEMGREP)
        self.assertEqual(canonical.category, FindingCategory.CRYPTO_API)
        self.assertEqual(canonical.source, FindingSource.SOURCE_CODE)
        self.assertEqual(canonical.algorithm, "RSA")
        self.assertEqual(canonical.file, "src/crypto_utils.py")
        self.assertEqual(canonical.line_start, 42)
        self.assertEqual(canonical.line_end, None)
        self.assertEqual(canonical.severity, "WARNING")
        self.assertEqual(canonical.finding_type, "ecdat.crypto.rsa")
        self.assertEqual(canonical.evidence.message, "RSA cipher initialization observed")
        self.assertEqual(canonical.metadata["language"], "python")

    def test_normalize_gitleaks_secret_finding_redaction(self) -> None:
        """Gitleaks secret finding preserves secret category and provenance while keeping secrets redacted."""
        gitleaks_json = json.dumps(
            [
                {
                    "Description": "AWS Access Key",
                    "File": "config/credentials.json",
                    "StartLine": 10,
                    "RuleID": "aws-access-token",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                    "Fingerprint": "config/credentials.json:aws-access-token:10",
                }
            ]
        )
        findings = GitleaksParser().parse(gitleaks_json, Path("/target"))
        self.assertEqual(len(findings), 1)

        canonical_list = FindingNormalizer().normalize(findings)
        self.assertEqual(len(canonical_list), 1)
        canonical = canonical_list[0]

        self.assertEqual(canonical.scanner, ToolName.GITLEAKS)
        self.assertEqual(canonical.category, FindingCategory.SECRET)
        self.assertEqual(canonical.source, FindingSource.SECRET_STORE)
        self.assertEqual(canonical.file, "config/credentials.json")
        self.assertEqual(canonical.line_start, 10)
        self.assertEqual(canonical.finding_type, "aws-access-token")

        # Crucial security verification: confirm raw secrets never leak in canonical model or serialization
        self.assertEqual(canonical.evidence.original["Secret"], "[REDACTED]")
        self.assertEqual(canonical.evidence.original["Match"], "[REDACTED]")
        serialized = canonical.to_json()
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_normalize_syft_component_finding(self) -> None:
        """Syft SBOM component maps package details without fabricating crypto algorithms or key sizes."""
        syft_json = json.dumps(
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
        findings = SyftParser().parse(syft_json, Path("/target"))
        self.assertEqual(len(findings), 1)

        canonical_list = FindingNormalizer().normalize(findings)
        self.assertEqual(len(canonical_list), 1)
        canonical = canonical_list[0]

        self.assertEqual(canonical.scanner, ToolName.SYFT)
        self.assertEqual(canonical.category, FindingCategory.COMPONENT)
        self.assertEqual(canonical.source, FindingSource.DEPENDENCY)
        self.assertEqual(canonical.package_name, "pycryptodome")
        self.assertEqual(canonical.package_version, "3.18.0")
        self.assertEqual(canonical.package_type, "python")
        self.assertEqual(canonical.file, "requirements.txt")

        # Verify no cryptographic fields were fabricated
        self.assertIsNone(canonical.algorithm)
        self.assertIsNone(canonical.key_size)
        self.assertIsNone(canonical.usage)

    def test_normalize_trivy_vulnerability_finding(self) -> None:
        """Trivy vulnerability finding maps vulnerability ID, package, severity, and fixed version."""
        trivy_json = json.dumps(
            {
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
                                "Title": "Side-channel flaw in PyCryptodome",
                            }
                        ],
                    }
                ]
            }
        )
        findings = TrivyParser().parse(trivy_json, Path("/target"))
        self.assertEqual(len(findings), 1)

        canonical_list = FindingNormalizer().normalize(findings)
        self.assertEqual(len(canonical_list), 1)
        canonical = canonical_list[0]

        self.assertEqual(canonical.scanner, ToolName.TRIVY)
        self.assertEqual(canonical.category, FindingCategory.VULNERABILITY)
        self.assertEqual(canonical.source, FindingSource.DEPENDENCY)
        self.assertEqual(canonical.vulnerability_id, "CVE-2023-49460")
        self.assertEqual(canonical.package_name, "pycryptodome")
        self.assertEqual(canonical.package_version, "3.18.0")
        self.assertEqual(canonical.fixed_version, "3.19.0")
        self.assertEqual(canonical.severity, "HIGH")
        self.assertEqual(canonical.file, "requirements.txt")

    def test_normalize_openssl_certificate_finding(self) -> None:
        """OpenSSL certificate finding maps certificate metadata, public-key algorithm, key size, and signature algorithm."""
        openssl_text = """
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 123456789 (0x75bcd15)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=ECDAT Root CA, O=ECDAT Org
        Validity
            Not Before: Sep  1 00:00:00 2026 GMT
            Not After : Sep  1 00:00:00 2027 GMT
        Subject: CN=ecdat.internal.local, O=ECDAT Org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:ecdat.internal.local, DNS:api.ecdat.internal.local
"""
        finding = OpenSSLParser().parse_x509(openssl_text, "certs/server.crt")
        self.assertIsNotNone(finding)

        canonical_list = FindingNormalizer().normalize(finding)
        self.assertEqual(len(canonical_list), 1)
        canonical = canonical_list[0]

        self.assertEqual(canonical.scanner, ToolName.OPENSSL)
        self.assertEqual(canonical.category, FindingCategory.CERTIFICATE)
        self.assertEqual(canonical.source, FindingSource.CERTIFICATE_FILE)
        self.assertEqual(canonical.subject, "CN=ecdat.internal.local, O=ECDAT Org")
        self.assertEqual(canonical.issuer, "CN=ECDAT Root CA, O=ECDAT Org")
        self.assertEqual(canonical.serial, "123456789 (0x75bcd15)")
        self.assertEqual(canonical.valid_from, "Sep  1 00:00:00 2026 GMT")
        self.assertEqual(canonical.valid_until, "Sep  1 00:00:00 2027 GMT")
        self.assertEqual(canonical.signature_algorithm, "sha256WithRSAEncryption")
        self.assertEqual(canonical.public_key_algorithm, "rsaEncryption")
        self.assertEqual(canonical.algorithm, "RSA")
        self.assertEqual(canonical.key_size, 2048)
        self.assertEqual(canonical.san, "DNS:ecdat.internal.local, DNS:api.ecdat.internal.local")
        self.assertEqual(canonical.file, "certs/server.crt")

    def test_missing_optional_fields_remain_null(self) -> None:
        """Unobserved optional fields are kept as None rather than empty strings or dummy fallbacks."""
        bare_finding = Finding(
            finding_id="bare-1",
            tool=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            evidence=ToolEvidence(message="Minimal finding"),
            metadata={},
        )
        canonical = FindingNormalizer().normalize_finding(bare_finding)

        self.assertIsNone(canonical.title)
        self.assertIsNone(canonical.algorithm)
        self.assertIsNone(canonical.key_size)
        self.assertIsNone(canonical.usage)
        self.assertIsNone(canonical.file)
        self.assertIsNone(canonical.line_start)
        self.assertIsNone(canonical.line_end)
        self.assertIsNone(canonical.package_name)
        self.assertIsNone(canonical.package_version)
        self.assertIsNone(canonical.package_type)
        self.assertIsNone(canonical.vulnerability_id)
        self.assertIsNone(canonical.fixed_version)
        self.assertIsNone(canonical.subject)
        self.assertIsNone(canonical.issuer)
        self.assertIsNone(canonical.serial)
        self.assertIsNone(canonical.valid_from)
        self.assertIsNone(canonical.valid_until)
        self.assertIsNone(canonical.signature_algorithm)
        self.assertIsNone(canonical.public_key_algorithm)
        self.assertIsNone(canonical.san)
        self.assertIsNone(canonical.protocol)
        self.assertIsNone(canonical.cipher)

    def test_normalization_preserves_scanner_provenance(self) -> None:
        """Every normalized finding retains exact tool, source, and raw_artifact provenance."""
        finding = Finding(
            finding_id="prov-1",
            tool=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.CONTAINER,
            evidence=ToolEvidence(message="Vuln", raw_artifact="raw/trivy.json"),
            metadata={},
        )
        canonical = FindingNormalizer().normalize_finding(finding)

        self.assertEqual(canonical.scanner, ToolName.TRIVY)
        self.assertEqual(canonical.category, FindingCategory.VULNERABILITY)
        self.assertEqual(canonical.source, FindingSource.CONTAINER)
        self.assertEqual(canonical.raw_artifact, "raw/trivy.json")

    def test_multiple_findings_and_scanner_results_in_one_call(self) -> None:
        """Normalizer accepts mixed collections of Finding and ScannerResult objects."""
        finding1 = Finding(
            finding_id="f1",
            tool=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            evidence=ToolEvidence(message="finding 1"),
            metadata={},
        )
        finding2 = Finding(
            finding_id="f2",
            tool=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            evidence=ToolEvidence(message="finding 2"),
            metadata={},
        )
        result = ScannerResult(
            scanner="syft",
            status=ScannerStatus.COMPLETED,
            message="done",
            findings=(finding2,),
        )

        canonical_batch = FindingNormalizer().normalize([finding1, result])
        self.assertEqual(len(canonical_batch), 2)
        self.assertEqual(canonical_batch[0].finding_id, "f1")
        self.assertEqual(canonical_batch[1].finding_id, "f2")

    def test_json_serialization(self) -> None:
        """CanonicalFinding serializes cleanly to JSON string and dictionary."""
        finding = Finding(
            finding_id="json-1",
            tool=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            evidence=ToolEvidence(message="AES-256 cipher"),
            metadata={"language": "python"},
            algorithm="AES",
            key_size=256,
            file="crypto.py",
            line=15,
        )
        canonical = FindingNormalizer().normalize_finding(finding)
        canonical_dict = canonical.to_dict()
        canonical_json = canonical.to_json()

        self.assertEqual(canonical_dict["finding_id"], "json-1")
        self.assertEqual(canonical_dict["scanner"], "semgrep")
        self.assertEqual(canonical_dict["algorithm"], "AES")
        self.assertEqual(canonical_dict["key_size"], 256)

        parsed = json.loads(canonical_json)
        self.assertEqual(parsed["finding_id"], "json-1")
        self.assertEqual(parsed["scanner"], "semgrep")
        self.assertEqual(parsed["algorithm"], "AES")
        self.assertEqual(parsed["key_size"], 256)
