"""Confidence and Cryptographic Classification Engine implementation for ECDAT."""

from __future__ import annotations

from typing import Sequence

from shared.models.finding import CryptoUsage, FindingCategory, ToolName
from scanner.models.canonical_finding import CanonicalFinding
from scanner.models.classified_asset import (
    ClassifiedCryptoAsset,
    CryptoClassification,
    EvidenceConfidence,
)
from scanner.models.unified_asset import AssetRelationship, UnifiedCryptoAsset
from scanner.normalizer.correlation_engine import CorrelationResult


class ConfidenceClassifier:
    """Classifies UnifiedCryptoAsset instances and evaluates evidence confidence."""

    # Canonical algorithm mapping
    _ALGORITHM_MAP = {
        "rsa": "RSA",
        "rsaencryption": "RSA",
        "sha256withrsaencryption": "RSA",
        "ecdsa": "ECDSA",
        "ec": "ECDSA",
        "ecdh": "ECDH",
        "ecdhe": "ECDH",
        "aes": "AES",
        "aes-128": "AES",
        "aes-256": "AES",
        "chacha20": "ChaCha20",
        "ed25519": "Ed25519",
        "ed448": "Ed448",
        "sha256": "SHA-256",
        "sha-256": "SHA-256",
        "sha384": "SHA-384",
        "sha-384": "SHA-384",
        "sha512": "SHA-512",
        "sha-512": "SHA-512",
        "sha1": "SHA-1",
        "sha-1": "SHA-1",
        "md5": "MD5",
    }

    # Algorithm specific categories
    _ENCRYPTION_ALGS = {"AES", "ChaCha20"}
    _HASH_ALGS = {"SHA-256", "SHA-384", "SHA-512", "SHA-1", "MD5"}
    _SIGNATURE_ALGS = {"Ed25519", "Ed448"}
    _KEY_EXCHANGE_ALGS = {"ECDH", "DH"}

    def normalize_algorithm(self, alg: str | None) -> str | None:
        """Normalize algorithm string to canonical representation without fabricating."""
        if not alg or not isinstance(alg, str):
            return None

        clean_alg = alg.strip().lower()
        if clean_alg in self._ALGORITHM_MAP:
            return self._ALGORITHM_MAP[clean_alg]

        for key, val in self._ALGORITHM_MAP.items():
            if key in clean_alg:
                return val

        # Reject generic non-algorithm terms
        if clean_alg in ("crypto", "secure", "key", "hashing", "unknown", "generic"):
            return None

        return alg.strip()

    def classify_asset(
        self, asset: UnifiedCryptoAsset, relationships: Sequence[AssetRelationship] = ()
    ) -> ClassifiedCryptoAsset:
        """Determine classification, confidence, and algorithm for a UnifiedCryptoAsset."""
        # Check if asset is supported by explicit relationships
        related_rel_count = sum(
            1 for r in relationships if r.source_asset_id == asset.asset_id or r.target_asset_id == asset.asset_id
        )

        canonical_alg = self.normalize_algorithm(asset.algorithm)
        key_size = asset.key_size
        usage = asset.usage

        # Strategy 1: Certificate
        if asset.asset_type == FindingCategory.CERTIFICATE:
            confidence = EvidenceConfidence.HIGH
            classification = CryptoClassification.CERTIFICATE
            summary = "X.509 certificate parsed with explicit public key metadata"
            return ClassifiedCryptoAsset.from_unified_asset(
                asset, classification, confidence, canonical_alg, key_size, usage, summary
            )

        # Strategy 2: Secret / Private Key
        if asset.asset_type == FindingCategory.SECRET:
            confidence = EvidenceConfidence.HIGH
            rule_id = asset.metadata.get("rule_id") or asset.canonical_name
            if "private" in str(rule_id).lower() or "key" in str(rule_id).lower() or "rsa" in str(rule_id).lower():
                classification = CryptoClassification.PRIVATE_KEY
                summary = "Explicit private key artifact detected by secret scanner"
            else:
                classification = CryptoClassification.CRYPTO_KEY
                summary = "Cryptographic credential or key artifact detected by secret scanner"

            if related_rel_count > 0:
                confidence = EvidenceConfidence.HIGH

            return ClassifiedCryptoAsset.from_unified_asset(
                asset, classification, confidence, canonical_alg, key_size, usage, summary
            )

        # Strategy 3: Crypto API Usage
        if asset.asset_type == FindingCategory.CRYPTO_API:
            classification = CryptoClassification.CRYPTO_API_USAGE
            # Refine classification based on algorithm type if known
            if canonical_alg in self._ENCRYPTION_ALGS:
                classification = CryptoClassification.ENCRYPTION_ALGORITHM
            elif canonical_alg in self._HASH_ALGS or usage == CryptoUsage.HASHING:
                classification = CryptoClassification.HASH_FUNCTION
            elif canonical_alg in self._SIGNATURE_ALGS or usage == CryptoUsage.DIGITAL_SIGNATURE:
                classification = CryptoClassification.SIGNATURE_ALGORITHM
            elif canonical_alg in self._KEY_EXCHANGE_ALGS or usage == CryptoUsage.KEY_EXCHANGE:
                classification = CryptoClassification.KEY_EXCHANGE_ALGORITHM

            # Confidence determination
            # High if explicit known algorithm + line start, or if co-located with secret via explicit relationship
            if related_rel_count > 0:
                confidence = EvidenceConfidence.HIGH
                summary = "Cryptographic API invocation correlated with co-located evidence"
            elif canonical_alg and asset.locations:
                confidence = EvidenceConfidence.HIGH
                summary = f"Explicit cryptographic API invocation of {canonical_alg} in source code"
            elif asset.locations:
                confidence = EvidenceConfidence.MEDIUM
                summary = "Cryptographic API usage pattern observed with partial context"
            else:
                confidence = EvidenceConfidence.LOW
                summary = "Ambiguous cryptographic source pattern"

            return ClassifiedCryptoAsset.from_unified_asset(
                asset, classification, confidence, canonical_alg, key_size, usage, summary
            )

        # Strategy 4: Component / Dependency
        if asset.asset_type == FindingCategory.COMPONENT:
            classification = CryptoClassification.CRYPTO_DEPENDENCY
            pkg_name = asset.metadata.get("package_name") or asset.canonical_name
            clean_pkg = str(pkg_name).lower()
            if any(k in clean_pkg for k in ("crypto", "ssl", "pycryptodome", "m2crypto", "bouncycastle", "sodium")):
                classification = CryptoClassification.CRYPTO_LIBRARY
                confidence = EvidenceConfidence.HIGH
                summary = f"Known cryptographic software library: {pkg_name}"
            else:
                confidence = EvidenceConfidence.MEDIUM
                summary = f"Software dependency component: {pkg_name}"

            return ClassifiedCryptoAsset.from_unified_asset(
                asset, classification, confidence, canonical_alg, key_size, usage, summary
            )

        # Strategy 5: Vulnerability
        if asset.asset_type == FindingCategory.VULNERABILITY:
            vuln_id = asset.vulnerabilities[0] if asset.vulnerabilities else asset.canonical_name
            # High confidence if connected to a package via explicit relationship
            if related_rel_count > 0:
                confidence = EvidenceConfidence.HIGH
                classification = CryptoClassification.CRYPTO_VULNERABILITY
                summary = f"Vulnerability {vuln_id} affecting correlated software component"
            else:
                confidence = EvidenceConfidence.MEDIUM
                classification = CryptoClassification.CRYPTO_VULNERABILITY
                summary = f"Vulnerability observation: {vuln_id}"

            return ClassifiedCryptoAsset.from_unified_asset(
                asset, classification, confidence, canonical_alg, key_size, usage, summary
            )

        # Strategy 6: Fallback / Unknown
        confidence = EvidenceConfidence.UNKNOWN
        classification = CryptoClassification.UNKNOWN_CRYPTO
        summary = "Unrecognized or ambiguous cryptographic artifact"
        return ClassifiedCryptoAsset.from_unified_asset(
            asset, classification, confidence, canonical_alg, key_size, usage, summary
        )

    def classify(self, correlation_result: CorrelationResult) -> tuple[ClassifiedCryptoAsset, ...]:
        """Classify all unified assets in a CorrelationResult in deterministic order."""
        relationships = correlation_result.relationships
        classified: list[ClassifiedCryptoAsset] = []

        for asset in correlation_result.unified_assets:
            classified.append(self.classify_asset(asset, relationships))

        # Sort deterministically by asset_id
        classified.sort(key=lambda c: c.asset_id)
        return tuple(classified)
