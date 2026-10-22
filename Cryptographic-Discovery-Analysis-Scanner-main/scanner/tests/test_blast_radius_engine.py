"""Comprehensive unit test suite for ECDAT Business Blast Radius Engine."""

import json
import unittest

from shared.models import CryptoUsage, ToolEvidence, ToolName
from scanner.models import (
    BlastRadiusAssessment,
    BlastRadiusLevel,
    BusinessAssetMapping,
    BusinessContext,
    BusinessCriticality,
    ClassifiedCryptoAsset,
    CryptoClassification,
    DataClassification,
    EvidenceConfidence,
    QuantumRiskAssessment,
    RiskLevel,
)
from scanner.risk import BlastRadiusEngine


class BlastRadiusEngineTests(unittest.TestCase):
    """Test BlastRadiusEngine scoring rules, multiple mappings, security, and determinism."""

    def setUp(self) -> None:
        """Initialize engine instance."""
        self.engine = BlastRadiusEngine()

    def test_1_critical_business_application_and_restricted_data(self) -> None:
        """Test 1: CRITICAL business application + RESTRICTED data -> CRITICAL blast radius."""
        asset = ClassifiedCryptoAsset(
            asset_id="asset-crit",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
        )
        ctx = BusinessContext(
            application_id="app-payment",
            application_name="Payment Gateway",
            criticality=BusinessCriticality.CRITICAL,
            data_classification=DataClassification.RESTRICTED,
        )
        mapping = BusinessAssetMapping(
            asset_id="asset-crit",
            application_id="app-payment",
            criticality=BusinessCriticality.CRITICAL,
            data_classification=DataClassification.RESTRICTED,
        )

        assessment = self.engine.assess(asset, [ctx], [mapping])
        self.assertEqual(assessment.blast_radius_level, BlastRadiusLevel.CRITICAL)
        self.assertGreaterEqual(assessment.impact_score, 70.0)
        self.assertIn("Payment Gateway", assessment.affected_applications)

    def test_2_low_criticality_and_public_data(self) -> None:
        """Test 2: LOW criticality + PUBLIC data -> SMALL blast radius."""
        asset = ClassifiedCryptoAsset(
            asset_id="asset-low",
            classification=CryptoClassification.HASH_FUNCTION,
            confidence=EvidenceConfidence.HIGH,
            algorithm="SHA-256",
        )
        ctx = BusinessContext(
            application_id="app-blog",
            application_name="Public Tech Blog",
            criticality=BusinessCriticality.LOW,
            data_classification=DataClassification.PUBLIC,
        )
        mapping = BusinessAssetMapping(
            asset_id="asset-low",
            application_id="app-blog",
            criticality=BusinessCriticality.LOW,
            data_classification=DataClassification.PUBLIC,
        )

        assessment = self.engine.assess(asset, [ctx], [mapping])
        self.assertEqual(assessment.blast_radius_level, BlastRadiusLevel.SMALL)
        self.assertLess(assessment.impact_score, 35.0)

    def test_3_same_crypto_asset_mapped_to_3_applications(self) -> None:
        """Test 3: Same crypto asset mapped to 3 applications -> all 3 applications included in output."""
        asset = ClassifiedCryptoAsset(
            asset_id="asset-shared",
            classification=CryptoClassification.CRYPTO_LIBRARY,
            confidence=EvidenceConfidence.HIGH,
            algorithm="AES",
        )
        m1 = BusinessAssetMapping(asset_id="asset-shared", application_id="app-1", service_name="auth-service")
        m2 = BusinessAssetMapping(asset_id="asset-shared", application_id="app-2", service_name="billing-service")
        m3 = BusinessAssetMapping(asset_id="asset-shared", application_id="app-3", service_name="user-service")

        assessment = self.engine.assess(asset, mappings=[m1, m2, m3])
        self.assertEqual(len(assessment.affected_applications), 3)
        self.assertEqual(assessment.affected_applications, ("app-1", "app-2", "app-3"))
        self.assertEqual(len(assessment.affected_services), 3)

    def test_4_duplicate_mappings_no_double_counting(self) -> None:
        """Test 4: Duplicate mappings for same asset and app -> deduplicated without double counting."""
        asset = ClassifiedCryptoAsset(
            asset_id="asset-dup",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
        )
        m1 = BusinessAssetMapping(asset_id="asset-dup", application_id="app-payment", service_name="pay-svc")
        m2 = BusinessAssetMapping(asset_id="asset-dup", application_id="app-payment", service_name="pay-svc")

        assessment = self.engine.assess(asset, mappings=[m1, m2])
        self.assertEqual(assessment.affected_applications, ("app-payment",))
        self.assertEqual(assessment.affected_services, ("pay-svc",))

    def test_5_multiple_affected_services(self) -> None:
        """Test 5: Multiple affected services increase system reach score contribution."""
        asset = ClassifiedCryptoAsset(asset_id="asset-multi-svc", classification=CryptoClassification.CRYPTO_LIBRARY, confidence=EvidenceConfidence.HIGH)
        m1 = BusinessAssetMapping(asset_id="asset-multi-svc", application_id="app-core", service_name="svc-a")
        m2 = BusinessAssetMapping(asset_id="asset-multi-svc", application_id="app-core", service_name="svc-b")

        assessment = self.engine.assess(asset, mappings=[m1, m2])
        self.assertEqual(len(assessment.affected_services), 2)

    def test_6_internet_exposed_asset(self) -> None:
        """Test 6: Internet-exposed asset adds exposure contribution when explicitly true."""
        asset = ClassifiedCryptoAsset(asset_id="asset-net", classification=CryptoClassification.CERTIFICATE, confidence=EvidenceConfidence.HIGH)
        ctx = BusinessContext(application_id="app-web", internet_exposed=True, criticality=BusinessCriticality.MEDIUM)
        mapping = BusinessAssetMapping(asset_id="asset-net", application_id="app-web", criticality=BusinessCriticality.MEDIUM)

        assessment = self.engine.assess(asset, [ctx], [mapping])
        self.assertTrue(assessment.internet_exposed)
        self.assertIn("Asset is exposed to the public internet", assessment.rationale)

    def test_7_internet_exposure_unknown(self) -> None:
        """Test 7: Internet exposure unknown -> no fabricated assumption of true/false."""
        asset = ClassifiedCryptoAsset(asset_id="asset-unk-net", classification=CryptoClassification.CRYPTO_KEY, confidence=EvidenceConfidence.HIGH)
        mapping = BusinessAssetMapping(asset_id="asset-unk-net", application_id="app-internal", criticality=BusinessCriticality.MEDIUM)

        assessment = self.engine.assess(asset, mappings=[mapping])
        self.assertIsNone(assessment.internet_exposed)

    def test_8_regulatory_scope_explicitly_provided(self) -> None:
        """Test 8: Regulatory scope provided -> contributes to impact score according to policy."""
        asset = ClassifiedCryptoAsset(asset_id="asset-reg", classification=CryptoClassification.CERTIFICATE, confidence=EvidenceConfidence.HIGH)
        ctx = BusinessContext(application_id="app-bank", regulatory_scope="RBI", criticality=BusinessCriticality.HIGH)
        mapping = BusinessAssetMapping(asset_id="asset-reg", application_id="app-bank", criticality=BusinessCriticality.HIGH)

        assessment = self.engine.assess(asset, [ctx], [mapping])
        self.assertEqual(assessment.regulatory_scopes, ("RBI",))
        self.assertIn("RBI", assessment.rationale)

    def test_9_missing_business_context(self) -> None:
        """Test 9: Missing business context -> UNKNOWN blast radius with explicit rationale."""
        asset = ClassifiedCryptoAsset(asset_id="asset-unmapped", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH)

        assessment = self.engine.assess(asset, mappings=[])
        self.assertEqual(assessment.blast_radius_level, BlastRadiusLevel.UNKNOWN)
        self.assertEqual(assessment.impact_score, 0.0)
        self.assertIn("Business context mapping is unavailable", assessment.rationale)

    def test_10_finding_order_does_not_affect_output(self) -> None:
        """Test 10: Finding order variations in batch assessment produce identical outputs."""
        asset1 = ClassifiedCryptoAsset(asset_id="a1", classification=CryptoClassification.CERTIFICATE, confidence=EvidenceConfidence.HIGH)
        asset2 = ClassifiedCryptoAsset(asset_id="a2", classification=CryptoClassification.HASH_FUNCTION, confidence=EvidenceConfidence.HIGH)
        m1 = BusinessAssetMapping(asset_id="a1", application_id="app-1")
        m2 = BusinessAssetMapping(asset_id="a2", application_id="app-2")

        res1 = self.engine.assess_batch([asset1, asset2], mappings=[m1, m2])
        res2 = self.engine.assess_batch([asset2, asset1], mappings=[m2, m1])

        self.assertEqual(res1[0].to_json(), res2[1].to_json())
        self.assertEqual(res1[1].to_json(), res2[0].to_json())

    def test_11_business_mapping_order_does_not_affect_output(self) -> None:
        """Test 11: Business mapping input order does not alter output blast radius."""
        asset = ClassifiedCryptoAsset(asset_id="asset-multi", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH)
        m1 = BusinessAssetMapping(asset_id="asset-multi", application_id="app-z")
        m2 = BusinessAssetMapping(asset_id="asset-multi", application_id="app-a")

        ass1 = self.engine.assess(asset, mappings=[m1, m2])
        ass2 = self.engine.assess(asset, mappings=[m2, m1])

        self.assertEqual(ass1.to_json(), ass2.to_json())
        self.assertEqual(ass1.affected_applications, ("app-a", "app-z"))

    def test_12_gitleaks_secret_content_never_appears_in_blast_radius(self) -> None:
        """Test 12: Secret content never leaks in BlastRadiusAssessment output or to_json()."""
        asset = ClassifiedCryptoAsset(
            asset_id="git-sec",
            classification=CryptoClassification.PRIVATE_KEY,
            confidence=EvidenceConfidence.HIGH,
            metadata={"secret": "[REDACTED]"},
        )
        mapping = BusinessAssetMapping(asset_id="git-sec", application_id="app-auth")

        assessment = self.engine.assess(asset, mappings=[mapping])
        serialized = assessment.to_json()

        self.assertNotIn("DUMMY_SECRET", serialized)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)

    def test_13_quantum_risk_assessment_can_be_accepted_without_recalculation(self) -> None:
        """Test 13: QuantumRiskAssessment is attached to BlastRadiusAssessment without recalculating quantum risk."""
        asset = ClassifiedCryptoAsset(asset_id="asset-q", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH)
        mapping = BusinessAssetMapping(asset_id="asset-q", application_id="app-core")
        q_risk = QuantumRiskAssessment(
            asset_id="asset-q",
            risk_level=RiskLevel.HIGH,
            risk_score=85.0,
            algorithm="RSA",
        )

        assessment = self.engine.assess(asset, mappings=[mapping], quantum_risk=q_risk)
        self.assertIsNotNone(assessment.quantum_risk)
        self.assertEqual(assessment.quantum_risk.risk_level, RiskLevel.HIGH)

    def test_14_two_assets_different_business_mappings_produce_separate_assessments(self) -> None:
        """Test 14: Two assets with identical algorithm but different business mappings produce distinct blast-radius assessments."""
        asset1 = ClassifiedCryptoAsset(asset_id="rsa-1", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")
        asset2 = ClassifiedCryptoAsset(asset_id="rsa-2", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")

        m1 = BusinessAssetMapping(asset_id="rsa-1", application_id="app-critical", criticality=BusinessCriticality.CRITICAL)
        m2 = BusinessAssetMapping(asset_id="rsa-2", application_id="app-low", criticality=BusinessCriticality.LOW)

        ass1 = self.engine.assess(asset1, mappings=[m1])
        ass2 = self.engine.assess(asset2, mappings=[m2])

        self.assertEqual(ass1.blast_radius_level, BlastRadiusLevel.CRITICAL)
        self.assertEqual(ass2.blast_radius_level, BlastRadiusLevel.SMALL)
        self.assertGreater(ass1.impact_score, ass2.impact_score)

    def test_15_same_asset_mapped_to_critical_vs_low_criticality(self) -> None:
        """Test 15: Same asset type mapped to CRITICAL vs LOW criticality application yields distinct impact levels."""
        asset = ClassifiedCryptoAsset(asset_id="asset-test", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH)

        m_crit = BusinessAssetMapping(asset_id="asset-test", application_id="app-crit", criticality=BusinessCriticality.CRITICAL)
        m_low = BusinessAssetMapping(asset_id="asset-test", application_id="app-low", criticality=BusinessCriticality.LOW)

        ass_crit = self.engine.assess(asset, mappings=[m_crit])
        ass_low = self.engine.assess(asset, mappings=[m_low])

        self.assertEqual(ass_crit.blast_radius_level, BlastRadiusLevel.CRITICAL)
        self.assertEqual(ass_low.blast_radius_level, BlastRadiusLevel.SMALL)
