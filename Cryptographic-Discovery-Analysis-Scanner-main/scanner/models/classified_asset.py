"""Cryptographic Classification, Confidence, and ClassifiedCryptoAsset models for ECDAT."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias

from shared.models.finding import (
    CryptoUsage,
    FindingCategory,
    ToolName,
    _require_non_empty,
    _validate_json,
)
from scanner.models.canonical_finding import CanonicalFinding
from scanner.models.unified_asset import UnifiedCryptoAsset

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


class CryptoClassification(str, Enum):
    """Controlled taxonomy for cryptographic asset classification."""

    CRYPTO_ALGORITHM = "CRYPTO_ALGORITHM"
    CRYPTO_API_USAGE = "CRYPTO_API_USAGE"
    CRYPTO_LIBRARY = "CRYPTO_LIBRARY"
    CRYPTO_KEY = "CRYPTO_KEY"
    PRIVATE_KEY = "PRIVATE_KEY"
    PUBLIC_KEY = "PUBLIC_KEY"
    CERTIFICATE = "CERTIFICATE"
    TLS_CONFIGURATION = "TLS_CONFIGURATION"
    CRYPTO_DEPENDENCY = "CRYPTO_DEPENDENCY"
    CRYPTO_VULNERABILITY = "CRYPTO_VULNERABILITY"
    HASH_FUNCTION = "HASH_FUNCTION"
    SIGNATURE_ALGORITHM = "SIGNATURE_ALGORITHM"
    ENCRYPTION_ALGORITHM = "ENCRYPTION_ALGORITHM"
    KEY_EXCHANGE_ALGORITHM = "KEY_EXCHANGE_ALGORITHM"
    UNKNOWN_CRYPTO = "UNKNOWN_CRYPTO"


class EvidenceConfidence(str, Enum):
    """Evidence-based confidence levels for asset classification."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ClassifiedCryptoAsset:
    """Classified cryptographic asset with evidence-based confidence and canonical details."""

    asset_id: str
    classification: CryptoClassification
    confidence: EvidenceConfidence

    algorithm: str | None = None
    key_size: int | None = None
    usage: CryptoUsage | None = None

    evidence_summary: str = ""
    supporting_finding_ids: tuple[str, ...] = field(default_factory=tuple)
    scanners: tuple[ToolName, ...] = field(default_factory=tuple)
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate classified asset invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        if not isinstance(self.classification, CryptoClassification):
            raise ValueError("classification must be a CryptoClassification")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise ValueError("confidence must be an EvidenceConfidence")
        if not isinstance(self.supporting_finding_ids, tuple):
            raise ValueError("supporting_finding_ids must be a tuple")
        if not isinstance(self.scanners, tuple):
            raise ValueError("scanners must be a tuple")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    @classmethod
    def from_unified_asset(
        cls,
        asset: UnifiedCryptoAsset,
        classification: CryptoClassification,
        confidence: EvidenceConfidence,
        algorithm: str | None,
        key_size: int | None,
        usage: CryptoUsage | None,
        evidence_summary: str,
    ) -> ClassifiedCryptoAsset:
        """Construct ClassifiedCryptoAsset from a UnifiedCryptoAsset and classifier outputs."""
        supporting_finding_ids = tuple(
            sorted({f.finding_id for f in asset.evidence if f.finding_id})
        )
        return cls(
            asset_id=asset.asset_id,
            classification=classification,
            confidence=confidence,
            algorithm=algorithm,
            key_size=key_size,
            usage=usage,
            evidence_summary=evidence_summary,
            supporting_finding_ids=supporting_finding_ids,
            scanners=asset.scanners,
            metadata=asset.metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "asset_id": self.asset_id,
            "classification": self.classification.value,
            "confidence": self.confidence.value,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "usage": self.usage.value if self.usage else None,
            "evidence_summary": self.evidence_summary,
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "scanners": [s.value for s in self.scanners],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
