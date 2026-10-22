"""Unit tests for Semgrep JSON parsing into ECDAT Findings."""

import json
import tempfile
import unittest
from pathlib import Path

from scanner.scanners.semgrep.parser import SemgrepParseError, SemgrepParser


class SemgrepParserTests(unittest.TestCase):
    """Verify only ECDAT crypto rules are normalized and evidence is retained."""

    def test_rule_pack_contains_required_crypto_discovery_rules(self) -> None:
        """The versioned local rule pack covers the phase-one algorithm scope."""
        rules_path = Path(__file__).parents[1] / "scanners" / "semgrep" / "rules" / "ecdat-crypto.yml"
        rules = rules_path.read_text(encoding="utf-8")

        for rule_id in (
            "ecdat.crypto.rsa",
            "ecdat.crypto.ecdsa",
            "ecdat.crypto.ecdh",
            "ecdat.crypto.aes",
            "ecdat.crypto.hashing",
        ):
            self.assertIn(rule_id, rules)

    def test_parses_crypto_finding_and_preserves_native_evidence(self) -> None:
        """RSA Semgrep output becomes one raw/normalized ECDAT Finding."""
        report = {
            "results": [
                {
                    "check_id": "ecdat.crypto.rsa",
                    "path": "src/crypto.py",
                    "start": {"line": 12, "col": 1},
                    "extra": {
                        "message": "RSA cryptographic API or identifier observed.",
                        "severity": "INFO",
                        "languages": ["python"],
                    },
                },
                {
                    "check_id": "unrelated.rule",
                    "path": "src/other.py",
                    "start": {"line": 1},
                    "extra": {"message": "Not ECDAT crypto discovery"},
                },
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            findings = SemgrepParser().parse(json.dumps(report), Path(directory))

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.algorithm, "RSA")
        self.assertEqual(finding.file, "src/crypto.py")
        self.assertEqual(finding.line, 12)
        self.assertEqual(finding.rule, "ecdat.crypto.rsa")
        self.assertEqual(finding.severity, "INFO")
        self.assertEqual(finding.metadata["language"], "python")
        self.assertEqual(finding.evidence.original, report["results"][0])
        self.assertEqual(finding.evidence.raw_pointer, "/results/0")

    def test_rejects_malformed_report(self) -> None:
        """Invalid JSON does not become a fabricated discovery finding."""
        with self.assertRaises(SemgrepParseError):
            SemgrepParser().parse("not json", Path("."))

    def test_removes_path_outside_target(self) -> None:
        """An out-of-target native path cannot escape the shared contract."""
        report = {
            "results": [
                {
                    "check_id": "ecdat.crypto.aes",
                    "path": "../outside.py",
                    "start": {"line": 3},
                    "extra": {"message": "AES observed"},
                }
            ]
        }

        finding = SemgrepParser().parse(json.dumps(report), Path("."))[0]
        self.assertIsNone(finding.file)
