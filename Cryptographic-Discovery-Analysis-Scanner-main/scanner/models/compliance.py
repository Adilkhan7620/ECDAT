"""Compliance Framework, Control, Applicability, and Assessment models for ECDAT."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias

from shared.models.finding import (
    CryptoUsage,
    FindingCategory,
    _require_non_empty,
    _validate_json,
)
from scanner.models.blast_radius import BlastRadiusLevel
from scanner.models.classified_asset import CryptoClassification
from scanner.models.pqc_recommendation import PqcMigrationRecommendation
from scanner.models.quantum_risk import RiskLevel

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


class ComplianceStatus(str, Enum):
    """Controlled compliance status categories for ECDAT policy mapping."""

    ALIGNED = "ALIGNED"
    REQUIRES_ATTENTION = "REQUIRES_ATTENTION"
    GAP = "GAP"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class PolicyApplicability(str, Enum):
    """Explicit framework applicability setting."""

    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ComplianceFramework:
    """Model representing a regulatory or organizational compliance framework."""

    framework_id: str
    name: str
    version: str
    description: str
    authority: str
    applicability: PolicyApplicability = PolicyApplicability.APPLICABLE
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate framework invariants."""
        _require_non_empty(self.framework_id, "framework_id")
        _require_non_empty(self.name, "name")
        _require_non_empty(self.version, "version")
        if not isinstance(self.applicability, PolicyApplicability):
            raise ValueError("applicability must be a PolicyApplicability")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "framework_id": self.framework_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "authority": self.authority,
            "applicability": self.applicability.value,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class PolicyControl:
    """Model representing a specific control requirement within a compliance framework."""

    control_id: str
    framework_id: str
    title: str
    description: str
    category: str
    applicable_algorithms: tuple[str, ...] = field(default_factory=tuple)
    applicable_classifications: tuple[CryptoClassification, ...] = field(default_factory=tuple)
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate control invariants."""
        _require_non_empty(self.control_id, "control_id")
        _require_non_empty(self.framework_id, "framework_id")
        _require_non_empty(self.title, "title")
        if not isinstance(self.applicable_algorithms, tuple):
            raise ValueError("applicable_algorithms must be a tuple")
        if not isinstance(self.applicable_classifications, tuple):
            raise ValueError("applicable_classifications must be a tuple")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "control_id": self.control_id,
            "framework_id": self.framework_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "applicable_algorithms": list(self.applicable_algorithms),
            "applicable_classifications": [c.value for c in self.applicable_classifications],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class ComplianceAssessment:
    """Assessment of an asset's alignment with a specific policy control."""

    asset_id: str
    framework_id: str
    control_id: str
    status: ComplianceStatus

    rationale: str
    evidence_summary: str = ""
    supporting_finding_ids: tuple[str, ...] = field(default_factory=tuple)

    quantum_risk_level: RiskLevel = RiskLevel.UNKNOWN
    blast_radius_level: BlastRadiusLevel = BlastRadiusLevel.UNKNOWN
    pqc_recommendation: PqcMigrationRecommendation | None = None
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate compliance assessment invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        _require_non_empty(self.framework_id, "framework_id")
        _require_non_empty(self.control_id, "control_id")
        if not isinstance(self.status, ComplianceStatus):
            raise ValueError("status must be a ComplianceStatus")
        if not isinstance(self.supporting_finding_ids, tuple):
            raise ValueError("supporting_finding_ids must be a tuple")
        if not isinstance(self.quantum_risk_level, RiskLevel):
            raise ValueError("quantum_risk_level must be a RiskLevel")
        if not isinstance(self.blast_radius_level, BlastRadiusLevel):
            raise ValueError("blast_radius_level must be a BlastRadiusLevel")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "asset_id": self.asset_id,
            "framework_id": self.framework_id,
            "control_id": self.control_id,
            "status": self.status.value,
            "rationale": self.rationale,
            "evidence_summary": self.evidence_summary,
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "quantum_risk_level": self.quantum_risk_level.value,
            "blast_radius_level": self.blast_radius_level.value,
            "pqc_recommendation": self.pqc_recommendation.to_dict() if self.pqc_recommendation else None,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class FrameworkComplianceResult:
    """Summary of policy alignment for an entire framework across assessed assets."""

    framework_id: str
    framework_name: str
    applicability: PolicyApplicability
    alignment_score: float
    total_assessments: int
    aligned_count: int
    requires_attention_count: int
    gap_count: int
    not_applicable_count: int
    unknown_count: int
    assessments: tuple[ComplianceAssessment, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "applicability": self.applicability.value,
            "alignment_score": round(self.alignment_score, 2),
            "total_assessments": self.total_assessments,
            "aligned_count": self.aligned_count,
            "requires_attention_count": self.requires_attention_count,
            "gap_count": self.gap_count,
            "not_applicable_count": self.not_applicable_count,
            "unknown_count": self.unknown_count,
            "assessments": [a.to_dict() for a in self.assessments],
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
