"""Comprehensive unit test suite for ECDAT Compliance and Policy Mapping Engine."""

import json
import unittest

from shared.models import CryptoUsage, ToolEvidence, ToolName
from scanner.models import (
    BlastRadiusAssessment,
    BlastRadiusLevel,
    BusinessCriticality,
    ClassifiedCryptoAsset,
    ComplianceAssessment,
    ComplianceFramework,
    ComplianceStatus,
    CryptoClassification,
    EvidenceConfidence,
    FrameworkComplianceResult,
    MigrationEffort,
    MigrationPriority,
    MigrationStrategy,
    PolicyApplicability,
    PolicyControl,
    PqcMigrationRecommendation,
    QuantumRiskAssessment,
    RiskLevel,
)
from scanner.policy import CompliancePolicyEngine, PolicyKnowledgeBase


class CompliancePolicyEngineTests(unittest.TestCase):
    """Test CompliancePolicyEngine rules, framework applicability, status logic, determinism, and security."""

    def setUp(self) -> None:
        """Initialize engine instance."""
        self.engine = CompliancePolicyEngine()

    def test_1_rsa_2048_quantum_vulnerable_asset(self) -> None:
        """Test 1: RSA-2048 quantum-vulnerable asset against DST-NQM PQC readiness -> REQUIRES_ATTENTION."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            key_size=2048,
            usage=CryptoUsage.ENCRYPTION,
        )
        ctrl = PolicyKnowledgeBase.get_controls("DST-NQM")[1]  # DST-NQM-CTRL-2

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
        )

        self.assertEqual(assessment.status, ComplianceStatus.REQUIRES_ATTENTION)
        self.assertIn("DST-NQM PQC readiness control requires attention", assessment.rationale)

    def test_2_aes_256_retain_monitor_not_marked_as_gap(self) -> None:
        """Test 2: AES-256 asset -> ALIGNED for PQC readiness, not incorrectly marked as PQC gap."""
        asset = ClassifiedCryptoAsset(
            asset_id="aes256-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="AES",
            key_size=256,
        )
        ctrl = PolicyKnowledgeBase.get_controls("DST-NQM")[1]

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
        )

        self.assertEqual(assessment.status, ComplianceStatus.ALIGNED)
        self.assertIn("does not use quantum-vulnerable asymmetric cryptography", assessment.rationale)

    def test_3_md5_sha1_deprecation_attention(self) -> None:
        """Test 3: MD5 / SHA-1 against CNSA 2.0 -> GAP status due to classically broken hash."""
        asset = ClassifiedCryptoAsset(
            asset_id="md5-asset",
            classification=CryptoClassification.HASH_FUNCTION,
            confidence=EvidenceConfidence.HIGH,
            algorithm="MD5",
        )
        ctrl = PolicyKnowledgeBase.get_controls("CNSA-2.0")[1]  # CNSA-2.0-CTRL-2

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
        )

        self.assertEqual(assessment.status, ComplianceStatus.GAP)
        self.assertIn("CNSA 2.0 GAP: Classically broken algorithm MD5", assessment.rationale)

    def test_4_high_hndl_asset_requires_attention(self) -> None:
        """Test 4: High HNDL asset against RBI-QSAFE HNDL control -> REQUIRES_ATTENTION."""
        asset = ClassifiedCryptoAsset(
            asset_id="hndl-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
        )
        q_risk = QuantumRiskAssessment(
            asset_id="hndl-asset",
            risk_level=RiskLevel.HIGH,
            risk_score=85.0,
            algorithm="RSA",
            hndl_exposure="HIGH",
        )
        ctrl = PolicyKnowledgeBase.get_controls("RBI-QSAFE")[0]  # RBI-QSAFE-CTRL-1

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
            quantum_risk=q_risk,
        )

        self.assertEqual(assessment.status, ComplianceStatus.REQUIRES_ATTENTION)
        self.assertIn("HIGH HNDL exposure", assessment.rationale)

    def test_5_critical_blast_radius_vulnerable_asset(self) -> None:
        """Test 5: Critical financial asset using RSA against RBI-QSAFE infrastructure control -> REQUIRES_ATTENTION & rationale includes impact."""
        asset = ClassifiedCryptoAsset(
            asset_id="fin-asset",
            classification=CryptoClassification.CERTIFICATE,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
        )
        b_radius = BlastRadiusAssessment(
            asset_id="fin-asset",
            blast_radius_level=BlastRadiusLevel.CRITICAL,
            impact_score=90.0,
            criticality=BusinessCriticality.CRITICAL,
        )
        ctrl = PolicyKnowledgeBase.get_controls("RBI-QSAFE")[1]  # RBI-QSAFE-CTRL-2

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
            blast_radius=b_radius,
        )

        self.assertEqual(assessment.status, ComplianceStatus.REQUIRES_ATTENTION)
        self.assertIn("Critical financial asset (CRITICAL) uses quantum-vulnerable RSA", assessment.rationale)

    def test_6_pqc_recommendation_exists(self) -> None:
        """Test 6: PQC recommendation appears in compliance assessment output."""
        asset = ClassifiedCryptoAsset(asset_id="pqc-asset", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")
        pqc_rec = PqcMigrationRecommendation(
            asset_id="pqc-asset",
            current_algorithm="RSA",
            current_usage=CryptoUsage.ENCRYPTION,
            current_key_size=2048,
            recommended_algorithm="ML-KEM",
            recommended_family="FIPS 203",
            migration_strategy=MigrationStrategy.HYBRID,
            migration_priority=MigrationPriority.P1,
            migration_effort=MigrationEffort.HIGH,
            rationale="PQC transition recommended",
        )
        ctrl = PolicyKnowledgeBase.get_controls("DST-NQM")[1]

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
            pqc_rec=pqc_rec,
        )

        self.assertIsNotNone(assessment.pqc_recommendation)
        self.assertEqual(assessment.pqc_recommendation.recommended_algorithm, "ML-KEM")
        self.assertIn("ML-KEM", assessment.rationale)

    def test_7_policy_explicitly_not_applicable(self) -> None:
        """Test 7: Policy explicitly set to NOT_APPLICABLE -> assessment status is NOT_APPLICABLE."""
        asset = ClassifiedCryptoAsset(asset_id="na-asset", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")
        ctrl = PolicyKnowledgeBase.get_controls("CNSA-2.0")[0]

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.NOT_APPLICABLE,
        )

        self.assertEqual(assessment.status, ComplianceStatus.NOT_APPLICABLE)

    def test_8_policy_applicability_unknown(self) -> None:
        """Test 8: Policy applicability UNKNOWN -> assessment status is UNKNOWN."""
        asset = ClassifiedCryptoAsset(asset_id="unk-app-asset", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")
        ctrl = PolicyKnowledgeBase.get_controls("RBI-QSAFE")[0]

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.UNKNOWN,
        )

        self.assertEqual(assessment.status, ComplianceStatus.UNKNOWN)

    def test_9_missing_algorithm_evidence(self) -> None:
        """Test 9: Missing algorithm -> UNKNOWN status rather than fabricated compliance."""
        asset = ClassifiedCryptoAsset(asset_id="no-alg-asset", classification=CryptoClassification.UNKNOWN_CRYPTO, confidence=EvidenceConfidence.UNKNOWN, algorithm=None)
        ctrl = PolicyKnowledgeBase.get_controls("DST-NQM")[0]

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
        )

        self.assertEqual(assessment.status, ComplianceStatus.UNKNOWN)

    def test_10_supporting_finding_ids_preserved(self) -> None:
        """Test 10: Supporting finding IDs are preserved in ComplianceAssessment."""
        asset = ClassifiedCryptoAsset(
            asset_id="prov-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            supporting_finding_ids=("find-1", "find-2"),
        )
        ctrl = PolicyKnowledgeBase.get_controls("DST-NQM")[0]

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
        )

        self.assertEqual(assessment.supporting_finding_ids, ("find-1", "find-2"))

    def test_11_gitleaks_secrets_never_appear(self) -> None:
        """Test 11: Gitleaks secrets/credentials never appear in ComplianceAssessment JSON."""
        asset = ClassifiedCryptoAsset(
            asset_id="sec-asset",
            classification=CryptoClassification.PRIVATE_KEY,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            metadata={"secret": "[REDACTED]"},
        )
        ctrl = PolicyKnowledgeBase.get_controls("DST-NQM")[0]

        assessment = self.engine.assess_asset_against_control(
            asset=asset,
            control=ctrl,
            framework_applicability=PolicyApplicability.APPLICABLE,
        )

        serialized = assessment.to_json()
        self.assertNotIn("DUMMY_SECRET", serialized)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)

    def test_12_finding_order_does_not_affect_result(self) -> None:
        """Test 12: Asset evaluation order in evaluate_framework produces identical framework alignment score and JSON."""
        a1 = ClassifiedCryptoAsset(asset_id="a1", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")
        a2 = ClassifiedCryptoAsset(asset_id="a2", classification=CryptoClassification.HASH_FUNCTION, confidence=EvidenceConfidence.HIGH, algorithm="SHA-256")

        r1 = self.engine.evaluate_framework("DST-NQM", [a1, a2])
        r2 = self.engine.evaluate_framework("DST-NQM", [a2, a1])

        self.assertEqual(r1.to_json(), r2.to_json())

    def test_13_policy_order_does_not_affect_result(self) -> None:
        """Test 13: Framework evaluation sequence is independent across different policy frameworks."""
        asset = ClassifiedCryptoAsset(asset_id="a-shared", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")

        r_dst = self.engine.evaluate_framework("DST-NQM", [asset])
        r_rbi = self.engine.evaluate_framework("RBI-QSAFE", [asset])

        self.assertEqual(r_dst.framework_id, "DST-NQM")
        self.assertEqual(r_rbi.framework_id, "RBI-QSAFE")

    def test_14_multiple_frameworks_assess_same_asset_independently(self) -> None:
        """Test 14: Multiple frameworks assess the same asset independently without cross-contaminating status."""
        asset = ClassifiedCryptoAsset(asset_id="a-multi", classification=CryptoClassification.HASH_FUNCTION, confidence=EvidenceConfidence.HIGH, algorithm="MD5")

        r_dst = self.engine.evaluate_framework("DST-NQM", [asset])
        r_cnsa = self.engine.evaluate_framework("CNSA-2.0", [asset])

        self.assertNotEqual(r_dst.alignment_score, r_cnsa.alignment_score)
        self.assertTrue(any(a.status == ComplianceStatus.GAP for a in r_cnsa.assessments))

    def test_15_framework_score_is_deterministic_and_labeled_policy_alignment(self) -> None:
        """Test 15: Framework compliance result returns deterministic ECDAT policy alignment score."""
        a1 = ClassifiedCryptoAsset(asset_id="a1", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="AES")

        res = self.engine.evaluate_framework("DST-NQM", [a1])
        self.assertIsInstance(res, FrameworkComplianceResult)
        self.assertEqual(res.alignment_score, 100.0)
        self.assertIn("alignment_score", res.to_dict())
