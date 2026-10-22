"""Comprehensive unit test suite for ECDAT Quantum Risk Engine."""

import json
import unittest

from shared.models import CryptoUsage, FindingCategory, FindingSource, ToolEvidence, ToolName
from scanner.models import (
    AlgorithmKnowledgeBase,
    ClassifiedCryptoAsset,
    CryptoClassification,
    EvidenceConfidence,
    QuantumRiskAssessment,
    QuantumVulnerabilityClass,
    RiskLevel,
)
from scanner.risk import QuantumRiskEngine


class QuantumRiskEngineTests(unittest.TestCase):
    """Test QuantumRiskEngine rules, Mosca timing condition, algorithm taxonomy, and security rules."""

    def setUp(self) -> None:
        """Initialize risk engine instance."""
        self.engine = QuantumRiskEngine()

    def test_1_rsa_2048_encryption_mosca_triggered(self) -> None:
        """Test 1: RSA-2048 encryption with data_lifetime=10, migration_time=3, CRQC=10 (10+3 > 10) -> HIGH/CRITICAL & rationale timing."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-asset-1",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            key_size=2048,
            usage=CryptoUsage.ENCRYPTION,
        )

        assessment = self.engine.assess(
            asset,
            data_lifetime_years=10.0,
            migration_time_years=3.0,
            years_until_crqc=10.0,
        )

        self.assertIn(assessment.risk_level, (RiskLevel.HIGH, RiskLevel.CRITICAL))
        self.assertEqual(assessment.hndl_exposure, "HIGH")
        self.assertIn("10.0 + 3.0 > 10.0", assessment.rationale)
        self.assertIn("Mosca timing condition IS triggered", assessment.rationale)

    def test_2_rsa_2048_encryption_mosca_not_triggered(self) -> None:
        """Test 2: RSA-2048 encryption with data_lifetime=3, migration_time=2, CRQC=10 (3+2 <= 10) -> Mosca not triggered."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-asset-2",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            key_size=2048,
            usage=CryptoUsage.ENCRYPTION,
        )

        assessment = self.engine.assess(
            asset,
            data_lifetime_years=3.0,
            migration_time_years=2.0,
            years_until_crqc=10.0,
        )

        self.assertEqual(assessment.risk_level, RiskLevel.HIGH)
        self.assertIn("Mosca timing condition is NOT triggered", assessment.rationale)

    def test_3_ecdsa_quantum_vulnerable_asymmetric_classification(self) -> None:
        """Test 3: ECDSA signature algorithm classified as Shor-vulnerable asymmetric signature."""
        asset = ClassifiedCryptoAsset(
            asset_id="ecdsa-asset",
            classification=CryptoClassification.SIGNATURE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="ECDSA",
            usage=CryptoUsage.DIGITAL_SIGNATURE,
        )

        assessment = self.engine.assess(asset)
        profile = AlgorithmKnowledgeBase.get_profile("ECDSA")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.vulnerability_class, QuantumVulnerabilityClass.SHOR_VULNERABLE)
        self.assertEqual(assessment.risk_level, RiskLevel.HIGH)

    def test_4_ecdh_quantum_vulnerable_key_exchange_classification(self) -> None:
        """Test 4: ECDH key exchange classified as Shor-vulnerable key exchange."""
        asset = ClassifiedCryptoAsset(
            asset_id="ecdh-asset",
            classification=CryptoClassification.KEY_EXCHANGE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="ECDH",
            usage=CryptoUsage.KEY_EXCHANGE,
        )

        assessment = self.engine.assess(asset)
        profile = AlgorithmKnowledgeBase.get_profile("ECDH")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.vulnerability_class, QuantumVulnerabilityClass.SHOR_VULNERABLE)
        self.assertEqual(assessment.risk_level, RiskLevel.HIGH)

    def test_5_aes_256_grover_affected_only(self) -> None:
        """Test 5: AES-256 is classified as Grover-affected only, retaining 128-bit post-quantum security."""
        asset = ClassifiedCryptoAsset(
            asset_id="aes-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="AES",
            key_size=256,
            usage=CryptoUsage.ENCRYPTION,
        )

        assessment = self.engine.assess(asset)
        profile = AlgorithmKnowledgeBase.get_profile("AES")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.vulnerability_class, QuantumVulnerabilityClass.GROVER_AFFECTED)
        self.assertNotEqual(assessment.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(assessment.risk_level, RiskLevel.LOW)

    def test_6_sha_256_hash_classification(self) -> None:
        """Test 6: SHA-256 hash function classified as Grover-affected, not Shor public-key vulnerable."""
        asset = ClassifiedCryptoAsset(
            asset_id="sha256-asset",
            classification=CryptoClassification.HASH_FUNCTION,
            confidence=EvidenceConfidence.HIGH,
            algorithm="SHA-256",
            usage=CryptoUsage.HASHING,
        )

        assessment = self.engine.assess(asset)
        profile = AlgorithmKnowledgeBase.get_profile("SHA-256")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.vulnerability_class, QuantumVulnerabilityClass.GROVER_AFFECTED)
        self.assertEqual(assessment.risk_level, RiskLevel.LOW)

    def test_7_missing_key_size_retained_as_none(self) -> None:
        """Test 7: Missing key size is retained as None without fabricating a default key size."""
        asset = ClassifiedCryptoAsset(
            asset_id="no-keysize-asset",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            key_size=None,
        )

        assessment = self.engine.assess(asset)
        self.assertIsNone(assessment.key_size)

    def test_8_missing_data_lifetime_hndl_cannot_be_calculated(self) -> None:
        """Test 8: Missing data lifetime sets hndl_exposure to POSSIBLE / UNKNOWN and notes limitation in rationale."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-no-lifetime",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            usage=CryptoUsage.ENCRYPTION,
        )

        assessment = self.engine.assess(asset, data_lifetime_years=None)
        self.assertEqual(assessment.hndl_exposure, "POSSIBLE")
        self.assertIn("Data lifetime is unavailable; HNDL timing assessment cannot be completed", assessment.rationale)

    def test_9_missing_crqc_horizon_uses_configurable_default(self) -> None:
        """Test 9: Missing CRQC horizon uses engine DEFAULT_YEARS_UNTIL_CRQC (10.0) visible in assessment output."""
        asset = ClassifiedCryptoAsset(
            asset_id="rsa-default-crqc",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            usage=CryptoUsage.ENCRYPTION,
        )

        assessment = self.engine.assess(asset, years_until_crqc=None)
        self.assertEqual(assessment.years_until_crqc, 10.0)

    def test_10_changing_finding_order_produces_identical_risk_output(self) -> None:
        """Test 10: Input order changes in batch assessment produce identical assessment results."""
        asset1 = ClassifiedCryptoAsset(
            asset_id="asset-1",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            key_size=2048,
        )
        asset2 = ClassifiedCryptoAsset(
            asset_id="asset-2",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="AES",
            key_size=256,
        )

        res1 = self.engine.assess_batch([asset1, asset2])
        res2 = self.engine.assess_batch([asset2, asset1])

        res1_map = {r.asset_id: r.to_json() for r in res1}
        res2_map = {r.asset_id: r.to_json() for r in res2}
        self.assertEqual(res1_map, res2_map)

    def test_11_gitleaks_secret_evidence_never_appears_in_risk_result(self) -> None:
        """Test 11: Secret contents or private key raw strings never appear in QuantumRiskAssessment or to_json()."""
        asset = ClassifiedCryptoAsset(
            asset_id="gitleaks-secret-asset",
            classification=CryptoClassification.PRIVATE_KEY,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            metadata={"secret": "[REDACTED]"},
        )

        assessment = self.engine.assess(asset)
        serialized = assessment.to_json()
        self.assertNotIn("DUMMY_SECRET_KEY", serialized)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)

    def test_12_low_confidence_unknown_crypto_asset_returns_unknown_risk(self) -> None:
        """Test 12: Low confidence / unknown asset produces UNKNOWN risk_level and 0.0 score."""
        asset = ClassifiedCryptoAsset(
            asset_id="unknown-asset",
            classification=CryptoClassification.UNKNOWN_CRYPTO,
            confidence=EvidenceConfidence.UNKNOWN,
            algorithm=None,
        )

        assessment = self.engine.assess(asset)
        self.assertEqual(assessment.risk_level, RiskLevel.UNKNOWN)
        self.assertEqual(assessment.risk_score, 0.0)

    def test_13_different_usage_rsa_encryption_vs_rsa_signature(self) -> None:
        """Test 13: RSA encryption vs RSA signature produces distinct rationale and risk contexts."""
        asset_enc = ClassifiedCryptoAsset(
            asset_id="rsa-enc",
            classification=CryptoClassification.ENCRYPTION_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            usage=CryptoUsage.ENCRYPTION,
        )
        asset_sig = ClassifiedCryptoAsset(
            asset_id="rsa-sig",
            classification=CryptoClassification.SIGNATURE_ALGORITHM,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            usage=CryptoUsage.DIGITAL_SIGNATURE,
        )

        assess_enc = self.engine.assess(asset_enc, data_lifetime_years=5.0)
        assess_sig = self.engine.assess(asset_sig, data_lifetime_years=5.0)

        self.assertIn("encryption", assess_enc.rationale)
        self.assertIn("digital_signature", assess_sig.rationale)
        self.assertNotEqual(assess_enc.hndl_exposure, assess_sig.hndl_exposure)

    def test_14_batch_assessment_produces_deterministic_results(self) -> None:
        """Test 14: Batch assessment produces deterministic tuple of assessment results."""
        asset1 = ClassifiedCryptoAsset(
            asset_id="b1",
            classification=CryptoClassification.CERTIFICATE,
            confidence=EvidenceConfidence.HIGH,
            algorithm="RSA",
            key_size=2048,
        )
        asset2 = ClassifiedCryptoAsset(
            asset_id="b2",
            classification=CryptoClassification.HASH_FUNCTION,
            confidence=EvidenceConfidence.HIGH,
            algorithm="SHA-256",
        )

        batch_result = self.engine.assess_batch([asset1, asset2])
        self.assertEqual(len(batch_result), 2)
        self.assertEqual(batch_result[0].asset_id, "b1")
        self.assertEqual(batch_result[1].asset_id, "b2")
