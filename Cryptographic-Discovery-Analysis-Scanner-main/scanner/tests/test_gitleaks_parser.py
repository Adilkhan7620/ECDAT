"""Unit tests for Gitleaks JSON parsing and secret redaction."""

import json
import tempfile
import unittest
from pathlib import Path

from shared.models import FindingCategory, ToolName
from scanner.scanners.gitleaks.parser import GitleaksParseError, GitleaksParser


class GitleaksParserTests(unittest.TestCase):
    """Verify Gitleaks JSON output is converted into ECDAT Findings with redacted secrets."""

    def test_parses_gitleaks_finding_and_redacts_sensitive_values(self) -> None:
        """Raw Secret and Match fields are redacted in stored evidence."""
        raw_json = json.dumps(
            [
                {
                    "Description": "AWS Access Key",
                    "File": "config/aws.env",
                    "StartLine": 12,
                    "RuleID": "aws-access-key",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                    "Entropy": 3.5,
                    "Fingerprint": "config/aws.env:aws-access-key:12",
                }
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            findings = GitleaksParser().parse(raw_json, Path(directory))

        self.assertEqual(len(findings), 1)
        finding = findings[0]

        self.assertEqual(finding.tool, ToolName.GITLEAKS)
        self.assertEqual(finding.category, FindingCategory.SECRET)
        self.assertEqual(finding.rule, "aws-access-key")
        self.assertEqual(finding.file, "config/aws.env")
        self.assertEqual(finding.line, 12)
        self.assertEqual(finding.metadata["entropy"], 3.5)

        # Confirm redaction
        self.assertEqual(finding.evidence.original["Secret"], "[REDACTED]")
        self.assertEqual(finding.evidence.original["Match"], "[REDACTED]")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(finding.to_dict()))

    def test_sanitize_raw_output_redacts_secret_and_match_fields(self) -> None:
        """sanitize_raw_output replaces Secret and Match values with [REDACTED] while keeping metadata."""
        raw_json = json.dumps(
            [
                {
                    "Description": "Generic Secret",
                    "File": "src/config.py",
                    "StartLine": 10,
                    "RuleID": "generic-api-key",
                    "Secret": "SUPER_SECRET_VALUE",
                    "Match": "SUPER_SECRET_VALUE",
                }
            ]
        )
        sanitized = GitleaksParser.sanitize_raw_output(raw_json)
        self.assertIsNotNone(sanitized)
        self.assertNotIn("SUPER_SECRET_VALUE", sanitized)
        self.assertIn("[REDACTED]", sanitized)
        self.assertIn("generic-api-key", sanitized)
        self.assertIn("src/config.py", sanitized)

    def test_handles_empty_results(self) -> None:
        """Empty string or empty JSON array returns an empty tuple of findings."""
        parser = GitleaksParser()
        self.assertEqual(parser.parse("", Path(".")), ())
        self.assertEqual(parser.parse("  ", Path(".")), ())
        self.assertEqual(parser.parse("[]", Path(".")), ())

    def test_rejects_malformed_report(self) -> None:
        """Invalid JSON or non-array JSON raises GitleaksParseError."""
        parser = GitleaksParser()
        with self.assertRaises(GitleaksParseError):
            parser.parse("invalid json", Path("."))

        with self.assertRaises(GitleaksParseError):
            parser.parse('{"key": "value"}', Path("."))

    def test_removes_path_outside_target(self) -> None:
        """Out-of-target relative paths are removed to prevent directory traversal."""
        raw_json = json.dumps(
            [
                {
                    "Description": "Secret outside",
                    "File": "../outside.env",
                    "StartLine": 1,
                    "RuleID": "generic-secret",
                    "Secret": "SECRET123",
                }
            ]
        )

        findings = GitleaksParser().parse(raw_json, Path("."))
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0].file)
