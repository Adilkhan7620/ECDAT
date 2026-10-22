"""Tests for the shared, scanner-independent Finding contract."""

import json
from pathlib import Path
import unittest

from shared.models import (
    CryptoUsage,
    Finding,
    FindingCategory,
    FindingSource,
    ToolEvidence,
    ToolName,
)


class FindingTests(unittest.TestCase):
    """Verify validation, evidence preservation, and portable serialization."""

    def test_to_dict_preserves_source_evidence(self) -> None:
        """Tool-native evidence is kept without becoming top-level schema fields."""
        finding = Finding(
            finding_id="finding-1",
            tool=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            evidence=ToolEvidence(
                message="Cryptographic API observed",
                original={"check_id": "ecdat.crypto.rsa", "extra": {"engine_kind": "OSS"}},
                raw_artifact="raw/semgrep.json",
                raw_pointer="/results/0",
            ),
            metadata={"rule_language": "python"},
            algorithm="RSA",
            key_size=2048,
            usage=CryptoUsage.DIGITAL_SIGNATURE,
            file="src/signing.py",
            line=27,
            confidence=0.9,
            severity="WARNING",
        )

        payload = finding.to_dict()
        self.assertEqual(payload["category"], "crypto_api")
        self.assertEqual(payload["evidence"]["original"]["check_id"], "ecdat.crypto.rsa")
        self.assertNotIn("quantum_risk", payload)
        self.assertEqual(json.loads(finding.to_json()), payload)

    def test_invalid_values_are_rejected(self) -> None:
        """Invalid paths and out-of-range source confidence fail at the boundary."""
        evidence = ToolEvidence(message="native evidence")
        with self.assertRaisesRegex(ValueError, "confidence"):
            Finding(
                "finding-1", ToolName.SEMGREP, FindingCategory.CRYPTO_API,
                FindingSource.SOURCE_CODE, evidence, {}, confidence=1.1,
            )
        with self.assertRaisesRegex(ValueError, "relative path"):
            Finding(
                "finding-1", ToolName.SEMGREP, FindingCategory.CRYPTO_API,
                FindingSource.SOURCE_CODE, evidence, {}, file="../outside.py",
            )

    def test_schema_document_declares_contract_boundary(self) -> None:
        """The shared JSON Schema remains valid JSON and excludes risk fields."""
        schema_path = Path(__file__).parents[2] / "shared" / "schemas" / "ecdat-finding.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        self.assertIn("evidence", schema["required"])
        self.assertIn("metadata", schema["required"])
        self.assertNotIn("quantum_risk", schema["properties"])
