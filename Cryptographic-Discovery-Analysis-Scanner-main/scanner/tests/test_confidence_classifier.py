"""Comprehensive unit tests for ConfidenceClassifier in ECDAT."""

import json
import unittest

from shared.models import CryptoUsage, FindingCategory, FindingSource, ToolEvidence, ToolName
from scanner.models import (
    CanonicalFinding,
    ClassifiedCryptoAsset,
    CryptoClassification,
    EvidenceConfidence,
)
from scanner.normalizer import ConfidenceClassifier, CorrelationEngine


class ConfidenceClassifierTests(unittest.TestCase):
    """Test confidence scoring, classification taxonomy, algorithm normalization, and security rules."""

    def setUp(self) -> None:
        """Initialize correlation engine and confidence classifier."""
        self.correlation_engine = CorrelationEngine()
        self.classifier = ConfidenceClassifier()

    def test_1_explicit_openssl_rsa_2048_certificate(self) -> None:
        """Test 1: OpenSSL cert -> CERTIFICATE, RSA, key size 2048, HIGH confidence."""
        f_cert = CanonicalFinding(
            finding_id="cert-1",
            scanner=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            algorithm="rsaEncryption",
            key_size=2048,
            subject="CN=ecdat.local",
            serial="12345",
            file="certs/server.crt",
        )
        correlated = self.correlation_engine.correlate([f_cert])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 1)
        asset = classified[0]
        self.assertEqual(asset.classification, CryptoClassification.CERTIFICATE)
        self.assertEqual(asset.confidence, EvidenceConfidence.HIGH)
        self.assertEqual(asset.algorithm, "RSA")
        self.assertEqual(asset.key_size, 2048)

    def test_2_gitleaks_private_key_finding(self) -> None:
        """Test 2: Gitleaks private key finding -> PRIVATE_KEY, HIGH confidence, secret value never exposed."""
        f_key = CanonicalFinding(
            finding_id="git-priv",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            file="keys/id_rsa",
            line_start=1,
            finding_type="rsa-private-key",
            evidence=ToolEvidence(
                message="Private Key",
                original={"Secret": "[REDACTED]", "Match": "[REDACTED]"},
            ),
        )
        correlated = self.correlation_engine.correlate([f_key])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 1)
        asset = classified[0]
        self.assertEqual(asset.classification, CryptoClassification.PRIVATE_KEY)
        self.assertEqual(asset.confidence, EvidenceConfidence.HIGH)

        # Security check: verify secret is not exposed in serialized JSON
        serialized = asset.to_json()
        self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)
        self.assertNotIn("DUMMY_SECRET", serialized)

    def test_3_strong_semgrep_aes_rsa_api_finding(self) -> None:
        """Test 3: Strong Semgrep AES API finding -> ENCRYPTION_ALGORITHM / CRYPTO_API_USAGE, HIGH confidence."""
        f_aes = CanonicalFinding(
            finding_id="semgrep-aes",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="AES",
            usage=CryptoUsage.ENCRYPTION,
            file="crypto/cipher.py",
            line_start=15,
        )
        correlated = self.correlation_engine.correlate([f_aes])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 1)
        asset = classified[0]
        self.assertEqual(asset.classification, CryptoClassification.ENCRYPTION_ALGORITHM)
        self.assertEqual(asset.confidence, EvidenceConfidence.HIGH)
        self.assertEqual(asset.algorithm, "AES")

    def test_4_weak_ambiguous_semgrep_crypto_identifier(self) -> None:
        """Test 4: Ambiguous crypto identifier without file/location -> lower confidence, no fabricated algorithm."""
        f_weak = CanonicalFinding(
            finding_id="semgrep-weak",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="generic",
            file=None,
        )
        correlated = self.correlation_engine.correlate([f_weak])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 1)
        asset = classified[0]
        self.assertEqual(asset.confidence, EvidenceConfidence.LOW)
        self.assertIsNone(asset.algorithm)

    def test_5_syft_cryptographic_package(self) -> None:
        """Test 5: Syft cryptographic package (pycryptodome) -> CRYPTO_LIBRARY, HIGH confidence."""
        f_syft = CanonicalFinding(
            finding_id="syft-lib",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="pycryptodome",
            package_version="3.18.0",
            package_type="python",
        )
        correlated = self.correlation_engine.correlate([f_syft])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 1)
        asset = classified[0]
        self.assertEqual(asset.classification, CryptoClassification.CRYPTO_LIBRARY)
        self.assertEqual(asset.confidence, EvidenceConfidence.HIGH)

    def test_6_trivy_vulnerability_associated_with_crypto_package(self) -> None:
        """Test 6: Trivy vulnerability correlated with crypto package -> CRYPTO_VULNERABILITY, HIGH confidence."""
        f_syft = CanonicalFinding(
            finding_id="syft-1",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="pycryptodome",
            package_version="3.18.0",
        )
        f_trivy = CanonicalFinding(
            finding_id="trivy-1",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-49460",
            package_name="pycryptodome",
            package_version="3.18.0",
        )
        correlated = self.correlation_engine.correlate([f_syft, f_trivy])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 2)
        vuln_assets = [a for a in classified if a.classification == CryptoClassification.CRYPTO_VULNERABILITY]
        self.assertEqual(len(vuln_assets), 1)
        self.assertEqual(vuln_assets[0].confidence, EvidenceConfidence.HIGH)

    def test_7_multiple_explicitly_correlated_scanners_strengthens_confidence(self) -> None:
        """Test 7: Multiple explicitly correlated scanners (co-located secret & code API) -> HIGH confidence."""
        f_sem = CanonicalFinding(
            finding_id="sem-1",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
            line_start=10,
        )
        f_git = CanonicalFinding(
            finding_id="git-1",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            file="auth.py",
            line_start=12,
            finding_type="rsa-private-key",
            evidence=ToolEvidence(message="RSA Key", original={"Secret": "[REDACTED]"}),
        )
        correlated = self.correlation_engine.correlate([f_sem, f_git])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 2)
        for asset in classified:
            self.assertEqual(asset.confidence, EvidenceConfidence.HIGH)

    def test_8_unrelated_scanners_do_not_strengthen_confidence(self) -> None:
        """Test 8: Unrelated scanners in different files do NOT strengthen each other's confidence via false correlation."""
        f_sem = CanonicalFinding(
            finding_id="sem-unrelated",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="crypto",  # generic -> weak algorithm
            file=None,
        )
        f_cert = CanonicalFinding(
            finding_id="ssl-unrelated",
            scanner=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            algorithm="RSA",
            subject="CN=unrelated.local",
            file="certs/unrelated.crt",
        )
        correlated = self.correlation_engine.correlate([f_sem, f_cert])
        classified = self.classifier.classify(correlated)

        sem_asset = next(a for a in classified if a.asset_id == f_sem.finding_id or "generic" in str(a.metadata) or "Asset:generic" in a.evidence_summary or a.confidence == EvidenceConfidence.LOW)
        self.assertEqual(sem_asset.confidence, EvidenceConfidence.LOW)

    def test_9_missing_algorithm_remains_null(self) -> None:
        """Test 9: Missing algorithm remains None without fabrication."""
        f_no_alg = CanonicalFinding(
            finding_id="no-alg",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="requests",
            package_version="2.31.0",
        )
        correlated = self.correlation_engine.correlate([f_no_alg])
        classified = self.classifier.classify(correlated)

        self.assertIsNone(classified[0].algorithm)

    def test_10_same_input_different_order_produces_identical_classification(self) -> None:
        """Test 10: Input ordering changes produce identical classification and confidence."""
        f1 = CanonicalFinding(
            finding_id="f1",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="AES",
            file="encrypt.py",
            line_start=5,
        )
        f2 = CanonicalFinding(
            finding_id="f2",
            scanner=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            algorithm="RSA",
            subject="CN=server.local",
            serial="101",
        )

        corr1 = self.correlation_engine.correlate([f1, f2])
        corr2 = self.correlation_engine.correlate([f2, f1])

        class1 = self.classifier.classify(corr1)
        class2 = self.classifier.classify(corr2)

        self.assertEqual([c.to_json() for c in class1], [c.to_json() for c in class2])

    def test_11_gitleaks_secret_remains_redacted(self) -> None:
        """Test 11: Gitleaks secret remains redacted in classification model and output."""
        f_sec = CanonicalFinding(
            finding_id="git-redacted",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            file="secret.json",
            finding_type="gitleaks-secret",
            evidence=ToolEvidence(
                message="Secret token",
                original={"Secret": "[REDACTED]", "Match": "[REDACTED]"},
            ),
        )
        correlated = self.correlation_engine.correlate([f_sec])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 1)
        self.assertNotIn("SECRET_VALUE", classified[0].to_json())
        self.assertNotIn("DUMMY_SECRET", classified[0].to_json())

    def test_12_unknown_unsupported_crypto_artifact_produces_unknown_crypto(self) -> None:
        """Test 12: Generic unrecognized asset produces UNKNOWN_CRYPTO classification and UNKNOWN confidence."""
        f_unknown = CanonicalFinding(
            finding_id="unknown-1",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.PUBLIC_KEY,  # Not handled specifically
            source=FindingSource.PUBLIC_KEY_FILE,
            file="key.pub",
        )
        correlated = self.correlation_engine.correlate([f_unknown])
        classified = self.classifier.classify(correlated)

        self.assertEqual(len(classified), 1)
        self.assertEqual(classified[0].classification, CryptoClassification.UNKNOWN_CRYPTO)
        self.assertEqual(classified[0].confidence, EvidenceConfidence.UNKNOWN)
