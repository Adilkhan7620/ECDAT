"""Unit tests for Syft SBOM JSON parsing and metadata extraction."""

import json
import tempfile
import unittest
from pathlib import Path

from shared.models import FindingCategory, FindingSource, ToolName
from scanner.scanners.syft.parser import SyftParseError, SyftParser


class SyftParserTests(unittest.TestCase):
    """Verify Syft SBOM JSON output is converted into ECDAT Finding component records."""

    def test_parses_syft_artifacts_and_extracts_metadata(self) -> None:
        """Syft artifact records become ECDAT Findings with preserved package metadata."""
        raw_json = json.dumps(
            {
                "artifacts": [
                    {
                        "name": "openssl",
                        "version": "3.0.2",
                        "type": "deb",
                        "purl": "pkg:deb/ubuntu/openssl@3.0.2",
                        "language": "c",
                        "licenses": [{"value": "Apache-2.0"}],
                        "locations": [{"path": "/usr/bin/openssl"}],
                        "foundBy": "dpkg-db-cataloger",
                    }
                ]
            }
        )

        with tempfile.TemporaryDirectory() as directory:
            findings = SyftParser().parse(raw_json, Path(directory))

        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertEqual(finding.tool, ToolName.SYFT)
        self.assertEqual(finding.category, FindingCategory.COMPONENT)
        self.assertEqual(finding.source, FindingSource.DEPENDENCY)
        self.assertEqual(finding.metadata["name"], "openssl")
        self.assertEqual(finding.metadata["version"], "3.0.2")
        self.assertEqual(finding.metadata["package_type"], "deb")
        self.assertEqual(finding.metadata["purl"], "pkg:deb/ubuntu/openssl@3.0.2")
        self.assertEqual(finding.metadata["found_by"], "dpkg-db-cataloger")

        # Verify no fabricated crypto properties were invented
        self.assertIsNone(finding.algorithm)
        self.assertIsNone(finding.key_size)
        self.assertIsNone(finding.usage)
        self.assertIsNone(finding.confidence)

    def test_handles_empty_results(self) -> None:
        """Empty JSON, missing artifacts, or empty artifacts array returns empty tuple."""
        parser = SyftParser()
        self.assertEqual(parser.parse("", Path(".")), ())
        self.assertEqual(parser.parse("  ", Path(".")), ())
        self.assertEqual(parser.parse('{"artifacts": []}', Path(".")), ())

    def test_rejects_malformed_report(self) -> None:
        """Invalid JSON or invalid top-level type raises SyftParseError."""
        parser = SyftParser()
        with self.assertRaises(SyftParseError):
            parser.parse("invalid json", Path("."))

        with self.assertRaises(SyftParseError):
            parser.parse("[]", Path("."))

    def test_removes_path_outside_target(self) -> None:
        """Out-of-target locations do not escape target directory boundary."""
        raw_json = json.dumps(
            {
                "artifacts": [
                    {
                        "name": "library",
                        "version": "1.0",
                        "locations": [{"path": "../outside/lib.so"}],
                    }
                ]
            }
        )

        findings = SyftParser().parse(raw_json, Path("."))
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0].file)
