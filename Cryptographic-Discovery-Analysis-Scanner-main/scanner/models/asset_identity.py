"""Asset Identity and Asset Group models for ECDAT discovery engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from shared.models.finding import (
    CryptoUsage,
    FindingCategory,
    ToolName,
    _require_non_empty,
    _validate_json,
)
from scanner.models.canonical_finding import CanonicalFinding

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class AssetIdentity:
    """Stable identity representation for a discovery asset."""

    asset_id: str
    asset_type: FindingCategory
    canonical_name: str

    algorithm: str | None = None
    key_size: int | None = None
    usage: CryptoUsage | None = None

    location: str | None = None
    line_start: int | None = None

    package_name: str | None = None
    package_version: str | None = None
    package_type: str | None = None
    vulnerability_id: str | None = None

    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    protocol: str | None = None
    cipher: str | None = None

    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate asset identity invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        if not isinstance(self.asset_type, FindingCategory):
            raise ValueError("asset_type must be a FindingCategory")
        _require_non_empty(self.canonical_name, "canonical_name")

        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable representation of AssetIdentity."""
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type.value,
            "canonical_name": self.canonical_name,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "usage": self.usage.value if self.usage else None,
            "location": self.location,
            "line_start": self.line_start,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "package_type": self.package_type,
            "vulnerability_id": self.vulnerability_id,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class AssetGroup:
    """Group of canonical findings that represent the same underlying asset."""

    identity: AssetIdentity
    findings: tuple[CanonicalFinding, ...]
    scanners: tuple[ToolName, ...] = field(init=False)

    def __post_init__(self) -> None:
        """Initialize and validate asset group."""
        if not isinstance(self.identity, AssetIdentity):
            raise ValueError("identity must be an AssetIdentity")
        if not self.findings:
            raise ValueError("findings must not be empty")

        # Derive deduplicated scanner names preserving deterministic order
        scanners_list: list[ToolName] = []
        for finding in self.findings:
            if not isinstance(finding, CanonicalFinding):
                raise ValueError("All items in findings must be CanonicalFinding instances")
            if finding.scanner not in scanners_list:
                scanners_list.append(finding.scanner)

        object.__setattr__(self, "scanners", tuple(scanners_list))

    @property
    def asset_id(self) -> str:
        """Return the stable asset ID."""
        return self.identity.asset_id

    @property
    def asset_type(self) -> FindingCategory:
        """Return the asset category/type."""
        return self.identity.asset_type

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable representation of AssetGroup."""
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type.value,
            "identity": self.identity.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "scanners": [scanner.value for scanner in self.scanners],
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
