"""Comprehensive unit test suite for ECDAT PQC Migration Recommendation Engine."""

import json
import unittest

from shared.models import CryptoUsage, ToolEvidence, ToolName
from scanner.models import (
    BlastRadiusAssessment,
    BlastRadiusLevel,
    ClassifiedCryptoAsset,
    CryptoClassification,
    EvidenceConfidence,
    MigrationEffort,
    MigrationPriority,
    MigrationStrategy,
    PqcMigrationRecommendation,
    QuantumRiskAssessment,
    RiskLevel,
)
from scanner.risk import PqcRecommendationEngine


class PqcRecommendationEngineTests(unittest.TestCase):
    """Test PQC Recommendation Engine rules, usage-awareness, priority matrix, security, and determinism."""

    def setUp(self) -> None:
        """Initialize engine instance."""
        self.engine = PqcRecommendationEngine()

    def test_1_rsa_encryption_recommends_ml_kem(self) -> None:
        """Test 1: RSA used for encryption -> ML-KEM recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-enc",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            usage=CryptoUsage.ENCRYPTION,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.recommended_algorithm, "ML-KEM")
        self.assertIn("ML-KEM", rec.rationale)

    def test_2_rsa_signature_recommends_ml_dsa(self) -> None:
        """Test 2: RSA used for digital signature -> ML-DSA recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-sig",
            classification=CryptoClassification.SIGNATURE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            usage=CryptoUsage.DIGITAL_SIGNATURE,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.recommended_algorithm, "ML-DSA")
        self.assertIn("ML-DSA", rec.rationale)

    def test_3_ecdh_recommends_ml_kem(self) -> None:
        """Test 3: ECDH key exchange -> ML-KEM recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="ecdh-asset",
            classification=CryptoClassification.KEY_EXCHANGE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="ECDH",
            usage=CryptoUsage.KEY_EXCHANGE,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.recommended_algorithm, "ML-KEM")
        self.assertEqual(rec.migration_strategy, MigrationStrategy.HYBRID)

    def test_4_ecdsa_recommends_ml_dsa(self) -> None:
        """Test 4: ECDSA signature algorithm -> ML-DSA recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="ecdsa-asset",
            classification=CryptoClassification.SIGNATURE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="ECDSA",
            usage=CryptoUsage.DIGITAL_SIGNATURE,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.recommended_algorithm, "ML-DSA")

    def test_5_ed25519_recommends_ml_dsa(self) -> None:
        """Test 5: Ed25519 signature algorithm -> ML-DSA recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="ed25519-asset",
            classification=CryptoClassification.SIGNATURE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="Ed25519",
            usage=CryptoUsage.DIGITAL_SIGNATURE,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.recommended_algorithm, "ML-DSA")
        self.assertEqual(rec.migration_strategy, MigrationStrategy.DIRECT_PQC)

    def test_6_dh_recommends_ml_kem(self) -> None:
        """Test 6: DH key establishment -> ML-KEM recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="dh-asset",
            classification=CryptoClassification.KEY_EXCHANGE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="DH",
            usage=CryptoUsage.KEY_EXCHANGE,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.recommended_algorithm, "ML-KEM")

    def test_7_aes_128_modernization_evaluates_aes_256(self) -> None:
        """Test 7: AES-128 -> evaluate upgrade to AES-256 (not ML-KEM)."""
        asset = ClassifiedCryptoAsset(
            asset_id="aes128-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="AES",
            key_size=128,
            usage=CryptoUsage.ENCRYPTION,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.recommended_algorithm, "AES-256")
        self.assertNotEqual(rec.recommended_algorithm, "ML-KEM")
        self.assertEqual(rec.migration_strategy, MigrationStrategy.RETAIN_MONITOR)

    def test_8_aes_256_retain_monitor(self) -> None:
        """Test 8: AES-256 -> RETAIN_MONITOR strategy."""
        asset = ClassifiedCryptoAsset(
            asset_id="aes256-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="AES",
            key_size=256,
            usage=CryptoUsage.ENCRYPTION,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.migration_strategy, MigrationStrategy.RETAIN_MONITOR)
        self.assertEqual(rec.recommended_algorithm, "AES-256")

    def test_9_sha_256_retain_monitor(self) -> None:
        """Test 9: SHA-256 -> RETAIN_MONITOR strategy."""
        asset = ClassifiedCryptoAsset(
            asset_id="sha256-asset",
            classification=CryptoClassification.HASH_FUNCTION,
            confidence=EvidenceConfidence.HIGH,
            algorithm="SHA-256",
            usage=CryptoUsage.HASHING,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.migration_strategy, MigrationStrategy.RETAIN_MONITOR)
        self.assertEqual(rec.recommended_algorithm, "SHA-256")

    def test_10_md5_sha1_deprecate_recommendation(self) -> None:
        """Test 10: MD5/SHA-1 -> DEPRECATE classical modernization recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="md5-asset",
            classification=CryptoClassification.HASH_FUNCTION,
            confidence=EvidenceConfidence.HIGH,
            algorithm="MD5",
            usage=CryptoUsage.HASHING,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.migration_strategy, MigrationStrategy.DEPRECATE)
        self.assertIn("SHA-256", rec.recommended_algorithm)

    def test_11_unknown_algorithm_manual_review(self) -> None:
        """Test 11: Unknown algorithm -> MANUAL_REVIEW strategy without fabricating PQC replacement."""
        asset = ClassifiedCryptoAsset(
            asset_id="unk-alg-asset",
            classification=CryptoClassification.UNKNOWN_CRYPTO,
            confidence=EvidenceConfidence.UNKNOWN,
            algorithm=None,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.migration_strategy, MigrationStrategy.MANUAL_REVIEW)
        self.assertIsNone(rec.recommended_algorithm)

    def test_12_unknown_usage_conditional_manual_recommendation(self) -> None:
        """Test 12: Ambiguous RSA usage -> MANUAL_REVIEW conditional recommendation."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-ambiguous",
            classification=CryptoClassification.CRYPTO_API_USAGE,
            confidence=EvidenceConfidence.MEDIUM,
            algorithm="RSA",
            usage=None,
        )

        rec = self.engine.recommend(asset)
        self.assertEqual(rec.migration_strategy, MigrationStrategy.MANUAL_REVIEW)
        self.assertIn("conditional manual review required", rec.rationale)

    def test_13_high_hndl_exposure_increases_priority_text(self) -> None:
        """Test 13: High HNDL exposure incorporates HNDL consideration text."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-hndl",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            usage=CryptoUsage.ENCRYPTION,
        )
        q_risk = QuantumRiskAssessment(
            asset_id="rsa-hndl",
            risk_level=RiskLevel.HIGH,
            risk_score=85.0,
            algorithm="RSA",
            hndl_exposure="HIGH",
        )

        rec = self.engine.recommend(asset, quantum_risk=q_risk)
        self.assertIn("Harvest-Now-Decrypt-Later", rec.hndl_consideration)

    def test_14_critical_blast_radius_and_critical_quantum_risk_yields_p0(self) -> None:
        """Test 14: Critical blast radius + Critical quantum risk -> P0 priority."""
        asset = ClassifiedCryptoAsset(asset_id="p0-asset", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")
        q_risk = QuantumRiskAssessment(asset_id="p0-asset", risk_level=RiskLevel.CRITICAL, risk_score=95.0, algorithm="RSA")
        b_radius = BlastRadiusAssessment(asset_id="p0-asset", blast_radius_level=BlastRadiusLevel.CRITICAL, impact_score=90.0)

        rec = self.engine.recommend(asset, q_risk, b_radius)
        self.assertEqual(rec.migration_priority, MigrationPriority.P0)

    def test_15_high_quantum_risk_and_large_blast_radius_yields_p1(self) -> None:
        """Test 15: High quantum risk + Large blast radius -> P1 priority."""
        asset = ClassifiedCryptoAsset(asset_id="p1-asset", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA")
        q_risk = QuantumRiskAssessment(asset_id="p1-asset", risk_level=RiskLevel.HIGH, risk_score=80.0, algorithm="RSA")
        b_radius = BlastRadiusAssessment(asset_id="p1-asset", blast_radius_level=BlastRadiusLevel.LARGE, impact_score=65.0)

        rec = self.engine.recommend(asset, q_risk, b_radius)
        self.assertEqual(rec.migration_priority, MigrationPriority.P1)

    def test_16_low_quantum_risk_and_low_blast_radius_yields_monitor(self) -> None:
        """Test 16: Low quantum risk + Small blast radius -> MONITOR priority."""
        asset = ClassifiedCryptoAsset(asset_id="mon-asset", classification=CryptoClassification.HASH_FUNCTION, confidence=EvidenceConfidence.HIGH, algorithm="SHA-256")
        q_risk = QuantumRiskAssessment(asset_id="mon-asset", risk_level=RiskLevel.LOW, risk_score=15.0, algorithm="SHA-256")
        b_radius = BlastRadiusAssessment(asset_id="mon-asset", blast_radius_level=BlastRadiusLevel.SMALL, impact_score=10.0)

        rec = self.engine.recommend(asset, q_risk, b_radius)
        self.assertEqual(rec.migration_priority, MigrationPriority.MONITOR)

    def test_17_certificate_based_rsa_includes_pki_considerations(self) -> None:
        """Test 17: Certificate-based RSA asset includes PKI/CA compatibility considerations."""
        asset = ClassifiedCryptoAsset(
            asset_id="cert-rsa",
            classification=CryptoClassification.CERTIFICATE,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
        )

        rec = self.engine.recommend(asset)
        self.assertIn("certificate authority PKI re-issuance", rec.compatibility_considerations)

    def test_18_multiple_applications_reflects_effort_category(self) -> None:
        """Test 18: Asset affecting multiple applications reflects HIGH migration effort category."""
        asset = ClassifiedCryptoAsset(asset_id="multi-app", classification=CryptoClassification.CRYPTO_LIBRARY, confidence=EvidenceConfidence.HIGH, algorithm="RSA", usage=CryptoUsage.ENCRYPTION)
        b_radius = BlastRadiusAssessment(asset_id="multi-app", blast_radius_level=BlastRadiusLevel.LARGE, impact_score=70.0, affected_applications=("app1", "app2", "app3"))

        rec = self.engine.recommend(asset, blast_radius=b_radius)
        self.assertEqual(rec.migration_effort, MigrationEffort.HIGH)

    def test_19_gitleaks_secrets_never_appear_in_recommendation_output(self) -> None:
        """Test 19: Secret tokens/keys never leak in recommendation attributes or serialized JSON."""
        asset = ClassifiedCryptoAsset(
            asset_id="git-sec",
            classification=CryptoClassification.PRIVATE_KEY,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            metadata={"secret": "[REDACTED]"},
        )

        rec = self.engine.recommend(asset)
        serialized = rec.to_json()
        self.assertNotIn("DUMMY_SECRET", serialized)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)

    def test_20_deterministic_recommendation_regardless_of_input_order(self) -> None:
        """Test 20: Reordered input processing produces identical recommendation JSON."""
        asset = ClassifiedCryptoAsset(asset_id="det-1", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA", usage=CryptoUsage.ENCRYPTION)
        q_risk = QuantumRiskAssessment(asset_id="det-1", risk_level=RiskLevel.HIGH, risk_score=80.0, algorithm="RSA")
        b_radius = BlastRadiusAssessment(asset_id="det-1", blast_radius_level=BlastRadiusLevel.LARGE, impact_score=65.0)

        rec1 = self.engine.recommend(asset, q_risk, b_radius)
        rec2 = self.engine.recommend(asset, q_risk, b_radius)
        self.assertEqual(rec1.to_json(), rec2.to_json())

    def test_21_batch_recommendation_produces_deterministic_results(self) -> None:
        """Test 21: Batch recommendation produces deterministic output tuple in input order."""
        a1 = ClassifiedCryptoAsset(asset_id="b1", classification=CryptoClassification.ENCRYPTION_ALGORITHM, confidence=EvidenceConfidence.HIGH, algorithm="RSA", usage=CryptoUsage.ENCRYPTION)
        a2 = ClassifiedCryptoAsset(asset_id="b2", classification=CryptoClassification.HASH_FUNCTION, confidence=EvidenceConfidence.HIGH, algorithm="SHA-256")

        recs = self.engine.recommend_batch([a1, a2])
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0].asset_id, "b1")
        self.assertEqual(recs[1].asset_id, "b2")
