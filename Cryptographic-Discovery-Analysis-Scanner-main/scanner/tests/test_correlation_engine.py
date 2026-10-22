"""Comprehensive unit tests for ECDAT Correlation Engine."""

import json
import unittest

from shared.models import FindingCategory, FindingSource, ToolEvidence, ToolName
from scanner.models import (
    AssetRelationship,
    CanonicalFinding,
    RelationshipType,
    UnifiedCryptoAsset,
)
from scanner.normalizer import CorrelationEngine, CorrelationResult


class CorrelationEngineTests(unittest.TestCase):
    """Test ECDAT Correlation Engine evidence-driven correlation rules and determinism."""

    def setUp(self) -> None:
        """Initialize correlation engine."""
        self.engine = CorrelationEngine()

    def test_1_two_identical_semgrep_findings_produce_one_logical_crypto_context(self) -> None:
        """Test 1: Two identical Semgrep findings group into one unified crypto asset."""
        f1 = CanonicalFinding(
            finding_id="sem-1",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
            line_start=20,
        )
        f2 = CanonicalFinding(
            finding_id="sem-2",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.SEMGREP if hasattr(FindingCategory, "SEMGREP") else FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
            line_start=20,
        )

        result = self.engine.correlate([f1, f2])
        self.assertEqual(len(result.unified_assets), 1)
        asset = result.unified_assets[0]
        self.assertEqual(asset.algorithm, "RSA")
        self.assertEqual(asset.locations, ("auth.py",))
        self.assertEqual(len(asset.evidence), 2)

    def test_2_same_rsa_algorithm_in_different_files_remains_separate(self) -> None:
        """Test 2: Same RSA algorithm in auth.py and payment.py remains separate assets."""
        f_auth = CanonicalFinding(
            finding_id="sem-auth",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
        )
        f_pay = CanonicalFinding(
            finding_id="sem-pay",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="payment.py",
        )

        result = self.engine.correlate([f_auth, f_pay])
        self.assertEqual(len(result.unified_assets), 2)
        asset_ids = {a.asset_id for a in result.unified_assets}
        self.assertEqual(len(asset_ids), 2)
        self.assertEqual(len(result.relationships), 0)

    def test_3_syft_package_and_matching_trivy_vulnerability_relationship(self) -> None:
        """Test 3: Syft package + matching Trivy vulnerability produces package asset and AFFECTED_BY relationship."""
        f_syft = CanonicalFinding(
            finding_id="syft-pkg",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="pycryptodome",
            package_version="3.18.0",
            package_type="python",
        )
        f_trivy = CanonicalFinding(
            finding_id="trivy-vuln",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-49460",
            package_name="pycryptodome",
            package_version="3.18.0",
        )

        result = self.engine.correlate([f_syft, f_trivy])
        self.assertEqual(len(result.unified_assets), 2)
        self.assertEqual(len(result.relationships), 1)

        rel = result.relationships[0]
        self.assertEqual(rel.relationship_type, RelationshipType.AFFECTED_BY)
        self.assertIn("Matching package name and version", rel.confidence_basis)
        self.assertIn("syft-pkg", rel.supporting_finding_ids)
        self.assertIn("trivy-vuln", rel.supporting_finding_ids)

    def test_4_same_vulnerability_against_different_package_versions_do_not_incorrectly_merge(self) -> None:
        """Test 4: Same vulnerability against pycryptodome 3.18.0 vs 3.17.0 creates separate vulnerability assets."""
        v1 = CanonicalFinding(
            finding_id="trivy-v1",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-49460",
            package_name="pycryptodome",
            package_version="3.18.0",
        )
        v2 = CanonicalFinding(
            finding_id="trivy-v2",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-49460",
            package_name="pycryptodome",
            package_version="3.17.0",
        )

        result = self.engine.correlate([v1, v2])
        self.assertEqual(len(result.unified_assets), 2)
        self.assertNotEqual(result.unified_assets[0].asset_id, result.unified_assets[1].asset_id)

    def test_5_openssl_certificate_links_to_observed_public_key_algorithm(self) -> None:
        """Test 5: OpenSSL certificate asset exposes observed RSA algorithm and key size."""
        cert_finding = CanonicalFinding(
            finding_id="openssl-cert",
            scanner=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            algorithm="RSA",
            key_size=2048,
            subject="CN=ecdat.local",
            serial="12345",
            file="certs/server.pem",
        )

        result = self.engine.correlate([cert_finding])
        self.assertEqual(len(result.unified_assets), 1)
        asset = result.unified_assets[0]
        self.assertEqual(asset.algorithm, "RSA")
        self.assertEqual(asset.key_size, 2048)
        self.assertEqual(asset.certificates, ({"subject": "CN=ecdat.local", "serial": "12345"},))

    def test_6_semgrep_rsa_and_unrelated_openssl_rsa_certificate_remain_separate(self) -> None:
        """Test 6: Semgrep RSA in code + OpenSSL RSA cert remain separate when no shared explicit context exists."""
        semgrep_rsa = CanonicalFinding(
            finding_id="semgrep-rsa",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="app.py",
        )
        openssl_cert = CanonicalFinding(
            finding_id="openssl-cert",
            scanner=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            algorithm="RSA",
            subject="CN=test.local",
            serial="999",
            file="certs/tls.pem",
        )

        result = self.engine.correlate([semgrep_rsa, openssl_cert])
        self.assertEqual(len(result.unified_assets), 2)
        self.assertEqual(len(result.relationships), 0)

    def test_7_finding_order_changes_produces_identical_assets_and_relationships(self) -> None:
        """Test 7: Changing finding input order produces exact same asset IDs and relationship IDs."""
        f1 = CanonicalFinding(
            finding_id="f1",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="pycryptodome",
            package_version="3.18.0",
        )
        f2 = CanonicalFinding(
            finding_id="f2",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-49460",
            package_name="pycryptodome",
            package_version="3.18.0",
        )

        res_forward = self.engine.correlate([f1, f2])
        res_reverse = self.engine.correlate([f2, f1])

        self.assertEqual(
            [a.asset_id for a in res_forward.unified_assets],
            [a.asset_id for a in res_reverse.unified_assets],
        )
        self.assertEqual(
            [r.relationship_id for r in res_forward.relationships],
            [r.relationship_id for r in res_reverse.relationships],
        )

    def test_8_scanner_order_changes_produces_identical_assets_and_relationships(self) -> None:
        """Test 8: Changing scanner execution order produces exact same assets and relationships."""
        f_syft = CanonicalFinding(
            finding_id="s1",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="openssl",
            package_version="1.1.1t",
        )
        f_trivy = CanonicalFinding(
            finding_id="t1",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-0286",
            package_name="openssl",
            package_version="1.1.1t",
        )

        r1 = self.engine.correlate([f_syft, f_trivy])
        r2 = self.engine.correlate([f_trivy, f_syft])

        self.assertEqual(r1.to_json(), r2.to_json())

    def test_9_gitleaks_secret_evidence_remains_redacted(self) -> None:
        """Test 9: Gitleaks secret evidence remains redacted in unified assets and relationships."""
        secret_finding = CanonicalFinding(
            finding_id="gitleaks-secret",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            file="keys/privkey.pem",
            line_start=5,
            evidence=ToolEvidence(
                message="Private Key",
                original={"Secret": "[REDACTED]", "Match": "[REDACTED]"},
            ),
        )

        result = self.engine.correlate([secret_finding])
        self.assertEqual(len(result.unified_assets), 1)

        serialized = result.to_json()
        self.assertNotIn("DUMMY_SECRET_KEY", serialized)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_10_relationship_provenance_contains_supporting_finding_ids(self) -> None:
        """Test 10: Relationship provenance explicitly contains supporting finding IDs."""
        f_pkg = CanonicalFinding(
            finding_id="pkg-123",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="cryptography",
            package_version="41.0.0",
        )
        f_vuln = CanonicalFinding(
            finding_id="vuln-456",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-38325",
            package_name="cryptography",
            package_version="41.0.0",
        )

        result = self.engine.correlate([f_pkg, f_vuln])
        self.assertEqual(len(result.relationships), 1)

        rel = result.relationships[0]
        self.assertEqual(rel.supporting_finding_ids, ("pkg-123", "vuln-456"))

    def test_11_repeated_correlation_produces_identical_ids(self) -> None:
        """Test 11: Repeated correlation runs produce identical asset and relationship IDs."""
        f_api = CanonicalFinding(
            finding_id="api-1",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="ECDSA",
            file="sign.py",
        )

        res1 = self.engine.correlate([f_api])
        res2 = self.engine.correlate([f_api])

        self.assertEqual(res1.unified_assets[0].asset_id, res2.unified_assets[0].asset_id)
        self.assertEqual(res1.to_json(), res2.to_json())

    def test_12_multiple_scanners_contribute_evidence_only_when_rule_permits(self) -> None:
        """Test 12: Co-located secret and crypto API finding in same file create RELATED_TO relationship."""
        f_semgrep = CanonicalFinding(
            finding_id="semgrep-api",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="crypto.py",
            line_start=12,
        )
        f_gitleaks = CanonicalFinding(
            finding_id="gitleaks-key",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            file="crypto.py",
            line_start=15,
            finding_type="rsa-private-key",
            evidence=ToolEvidence(
                message="RSA Key",
                original={"Secret": "[REDACTED]"},
            ),
        )

        result = self.engine.correlate([f_semgrep, f_gitleaks])
        self.assertEqual(len(result.unified_assets), 2)
        self.assertEqual(len(result.relationships), 1)

        rel = result.relationships[0]
        self.assertEqual(rel.relationship_type, RelationshipType.RELATED_TO)
        self.assertIn("gitleaks-key", rel.supporting_finding_ids)
        self.assertIn("semgrep-api", rel.supporting_finding_ids)
