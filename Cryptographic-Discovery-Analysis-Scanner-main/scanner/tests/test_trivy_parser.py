"""Unit tests for Trivy JSON parsing and vulnerability extraction."""

import json
import tempfile
import unittest
from pathlib import Path

from shared.models import FindingCategory, FindingSource, ToolName
from scanner.scanners.trivy.parser import TrivyParseError, TrivyParser


class TrivyParserTests(unittest.TestCase):
    """Verify Trivy JSON output is converted into ECDAT Finding vulnerability records."""

    def test_parses_trivy_vulnerabilities_and_extracts_metadata(self) -> None:
        """Trivy vulnerability items become ECDAT Findings with preserved metadata."""
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
                            },
                            {
                                "VulnerabilityID": "CVE-2023-38325",
                                "PkgName": "cryptography",
                                "InstalledVersion": "40.0.0",
                                "FixedVersion": "41.0.2",
                                "Severity": "MEDIUM",
                                "Title": "Null pointer dereference in OpenSSL bindings",
                                "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-38325",
                            },
                        ],
                    }
                ],
            }
        )

        with tempfile.TemporaryDirectory() as directory:
            findings = TrivyParser().parse(raw_json, Path(directory))

        self.assertEqual(len(findings), 2)

        # High vulnerability
        high_finding = findings[0]
        self.assertEqual(high_finding.tool, ToolName.TRIVY)
        self.assertEqual(high_finding.category, FindingCategory.VULNERABILITY)
        self.assertEqual(high_finding.source, FindingSource.DEPENDENCY)
        self.assertEqual(high_finding.rule, "CVE-2023-49460")
        self.assertEqual(high_finding.severity, "HIGH")
        self.assertEqual(high_finding.file, "requirements.txt")
        self.assertEqual(high_finding.metadata["vulnerability_id"], "CVE-2023-49460")
        self.assertEqual(high_finding.metadata["package_name"], "pycryptodome")
        self.assertEqual(high_finding.metadata["installed_version"], "3.18.0")
        self.assertEqual(high_finding.metadata["fixed_version"], "3.19.0")

        # Medium vulnerability
        med_finding = findings[1]
        self.assertEqual(med_finding.rule, "CVE-2023-38325")
        self.assertEqual(med_finding.severity, "MEDIUM")
        self.assertEqual(med_finding.metadata["package_name"], "cryptography")

        # Verify no fabricated crypto properties were invented
        self.assertIsNone(high_finding.algorithm)
        self.assertIsNone(high_finding.key_size)
        self.assertIsNone(high_finding.usage)
        self.assertIsNone(high_finding.confidence)

    def test_handles_empty_results(self) -> None:
        """Empty JSON, missing Results, or empty Results array returns empty tuple."""
        parser = TrivyParser()
        self.assertEqual(parser.parse("", Path(".")), ())
        self.assertEqual(parser.parse("  ", Path(".")), ())
        self.assertEqual(parser.parse('{"Results": []}', Path(".")), ())

    def test_rejects_malformed_report(self) -> None:
        """Invalid JSON or non-dict top-level raises TrivyParseError."""
        parser = TrivyParser()
        with self.assertRaises(TrivyParseError):
            parser.parse("invalid json", Path("."))

        with self.assertRaises(TrivyParseError):
            parser.parse("[]", Path("."))

    def test_removes_path_outside_target(self) -> None:
        """Out-of-target locations do not escape target directory boundary."""
        raw_json = json.dumps(
            {
                "Results": [
                    {
                        "Target": "../outside/requirements.txt",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-0001",
                                "PkgName": "lib",
                                "InstalledVersion": "1.0",
                            }
                        ],
                    }
                ]
            }
        )

        findings = TrivyParser().parse(raw_json, Path("."))
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0].file)
