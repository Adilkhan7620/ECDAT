"""Unified Crypto Asset and Asset Relationship models for ECDAT Correlation Engine."""

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
from scanner.models.asset_identity import AssetGroup, AssetIdentity
from scanner.models.canonical_finding import CanonicalFinding

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


class RelationshipType(str, Enum):
    """Explicit correlation relationship types between discovery assets."""

    USES_ALGORITHM = "USES_ALGORITHM"
    RELATED_TO = "RELATED_TO"
    PROVIDES_CRYPTO_LIBRARY = "PROVIDES_CRYPTO_LIBRARY"
    AFFECTED_BY = "AFFECTED_BY"


@dataclass(frozen=True, slots=True)
class AssetRelationship:
    """Explicit relationship between two discovery assets."""

    relationship_id: str
    source_asset_id: str
    relationship_type: RelationshipType
    target_asset_id: str
    confidence_basis: str
    supporting_finding_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate relationship invariants."""
        _require_non_empty(self.relationship_id, "relationship_id")
        _require_non_empty(self.source_asset_id, "source_asset_id")
        if not isinstance(self.relationship_type, RelationshipType):
            raise ValueError("relationship_type must be a RelationshipType")
        _require_non_empty(self.target_asset_id, "target_asset_id")
        _require_non_empty(self.confidence_basis, "confidence_basis")
        if not isinstance(self.supporting_finding_ids, tuple):
            raise ValueError("supporting_finding_ids must be a tuple")
        for finding_id in self.supporting_finding_ids:
            _require_non_empty(finding_id, "supporting_finding_ids item")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "relationship_id": self.relationship_id,
            "source_asset_id": self.source_asset_id,
            "relationship_type": self.relationship_type.value,
            "target_asset_id": self.target_asset_id,
            "confidence_basis": self.confidence_basis,
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class UnifiedCryptoAsset:
    """Unified cryptographic asset representation combining grouped evidence and identity."""

    asset_id: str
    asset_type: FindingCategory
    canonical_name: str

    algorithm: str | None = None
    key_size: int | None = None
    usage: CryptoUsage | None = None

    locations: tuple[str, ...] = field(default_factory=tuple)
    packages: tuple[dict[str, str], ...] = field(default_factory=tuple)
    certificates: tuple[dict[str, str], ...] = field(default_factory=tuple)
    vulnerabilities: tuple[str, ...] = field(default_factory=tuple)

    evidence: tuple[CanonicalFinding, ...] = field(default_factory=tuple)
    scanners: tuple[ToolName, ...] = field(default_factory=tuple)
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate unified asset invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        if not isinstance(self.asset_type, FindingCategory):
            raise ValueError("asset_type must be a FindingCategory")
        _require_non_empty(self.canonical_name, "canonical_name")

        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    @classmethod
    def from_asset_group(cls, group: AssetGroup) -> UnifiedCryptoAsset:
        """Build UnifiedCryptoAsset from an AssetGroup."""
        identity = group.identity
        findings = group.findings

        locations_set: set[str] = set()
        packages_set: set[tuple[str, str]] = set()
        certificates_set: set[tuple[str, str]] = set()
        vulnerabilities_set: set[str] = set()

        for f in findings:
            if f.file:
                locations_set.add(f.file)
            if f.package_name:
                packages_set.add((f.package_name, f.package_version or "unknown"))
            if f.subject or f.serial:
                certificates_set.add((f.subject or "unknown", f.serial or "unknown"))
            if f.vulnerability_id:
                vulnerabilities_set.add(f.vulnerability_id)

        locations_tuple = tuple(sorted(locations_set))
        packages_tuple = tuple(
            {"name": pkg[0], "version": pkg[1]} for pkg in sorted(packages_set)
        )
        certificates_tuple = tuple(
            {"subject": cert[0], "serial": cert[1]} for cert in sorted(certificates_set)
        )
        vulnerabilities_tuple = tuple(sorted(vulnerabilities_set))

        return cls(
            asset_id=identity.asset_id,
            asset_type=identity.asset_type,
            canonical_name=identity.canonical_name,
            algorithm=identity.algorithm,
            key_size=identity.key_size,
            usage=identity.usage,
            locations=locations_tuple,
            packages=packages_tuple,
            certificates=certificates_tuple,
            vulnerabilities=vulnerabilities_tuple,
            evidence=findings,
            scanners=group.scanners,
            metadata=identity.metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type.value,
            "canonical_name": self.canonical_name,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "usage": self.usage.value if self.usage else None,
            "locations": list(self.locations),
            "packages": list(self.packages),
            "certificates": list(self.certificates),
            "vulnerabilities": list(self.vulnerabilities),
            "evidence": [f.to_dict() for f in self.evidence],
            "scanners": [s.value for s in self.scanners],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
