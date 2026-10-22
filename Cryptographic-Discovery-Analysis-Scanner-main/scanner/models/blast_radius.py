"""Business Context, Asset Mapping, and Blast Radius models for ECDAT."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias

from shared.models.finding import (
    _require_non_empty,
    _validate_json,
)
from scanner.models.quantum_risk import QuantumRiskAssessment

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


class BusinessCriticality(str, Enum):
    """Business criticality levels for applications and services."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class DataClassification(str, Enum):
    """Sensitivity classification levels for organizational data."""

    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"
    INTERNAL = "INTERNAL"
    PUBLIC = "PUBLIC"
    UNKNOWN = "UNKNOWN"


class BlastRadiusLevel(str, Enum):
    """Impact rating levels for business blast radius assessment."""

    CRITICAL = "CRITICAL"
    LARGE = "LARGE"
    MEDIUM = "MEDIUM"
    SMALL = "SMALL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class BusinessContext:
    """Explicit business context describing an application or service."""

    application_id: str
    application_name: str | None = None
    service_name: str | None = None
    business_function: str | None = None
    criticality: BusinessCriticality = BusinessCriticality.UNKNOWN
    data_classification: DataClassification = DataClassification.UNKNOWN
    internet_exposed: bool | None = None
    regulatory_scope: str | None = None
    owner: str | None = None
    environment: str | None = None
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate business context invariants."""
        _require_non_empty(self.application_id, "application_id")
        if not isinstance(self.criticality, BusinessCriticality):
            raise ValueError("criticality must be a BusinessCriticality")
        if not isinstance(self.data_classification, DataClassification):
            raise ValueError("data_classification must be a DataClassification")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "application_id": self.application_id,
            "application_name": self.application_name,
            "service_name": self.service_name,
            "business_function": self.business_function,
            "criticality": self.criticality.value,
            "data_classification": self.data_classification.value,
            "internet_exposed": self.internet_exposed,
            "regulatory_scope": self.regulatory_scope,
            "owner": self.owner,
            "environment": self.environment,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class BusinessAssetMapping:
    """Explicit mapping linking a discovery asset to a business context."""

    asset_id: str
    application_id: str
    service_name: str | None = None
    business_function: str | None = None
    criticality: BusinessCriticality = BusinessCriticality.UNKNOWN
    data_classification: DataClassification = DataClassification.UNKNOWN
    dependency_type: str | None = None
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate asset mapping invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        _require_non_empty(self.application_id, "application_id")
        if not isinstance(self.criticality, BusinessCriticality):
            raise ValueError("criticality must be a BusinessCriticality")
        if not isinstance(self.data_classification, DataClassification):
            raise ValueError("data_classification must be a DataClassification")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "asset_id": self.asset_id,
            "application_id": self.application_id,
            "service_name": self.service_name,
            "business_function": self.business_function,
            "criticality": self.criticality.value,
            "data_classification": self.data_classification.value,
            "dependency_type": self.dependency_type,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class BlastRadiusAssessment:
    """Assessment of organizational impact and blast radius for a discovery asset."""

    asset_id: str
    blast_radius_level: BlastRadiusLevel
    impact_score: float

    affected_applications: tuple[str, ...] = field(default_factory=tuple)
    affected_services: tuple[str, ...] = field(default_factory=tuple)
    affected_business_functions: tuple[str, ...] = field(default_factory=tuple)
    affected_data_classifications: tuple[DataClassification, ...] = field(default_factory=tuple)

    criticality: BusinessCriticality = BusinessCriticality.UNKNOWN
    internet_exposed: bool | None = None
    regulatory_scopes: tuple[str, ...] = field(default_factory=tuple)

    quantum_risk: QuantumRiskAssessment | None = None

    rationale: str = ""
    contributing_factors: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate blast radius assessment invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        if not isinstance(self.blast_radius_level, BlastRadiusLevel):
            raise ValueError("blast_radius_level must be a BlastRadiusLevel")
        if isinstance(self.impact_score, bool) or not isinstance(self.impact_score, (int, float)):
            raise ValueError("impact_score must be a numeric value between 0 and 100")
        if not 0.0 <= float(self.impact_score) <= 100.0:
            raise ValueError("impact_score must be between 0.0 and 100.0")
        if not isinstance(self.criticality, BusinessCriticality):
            raise ValueError("criticality must be a BusinessCriticality")
        if not isinstance(self.affected_applications, tuple):
            raise ValueError("affected_applications must be a tuple")
        if not isinstance(self.affected_services, tuple):
            raise ValueError("affected_services must be a tuple")
        if not isinstance(self.affected_business_functions, tuple):
            raise ValueError("affected_business_functions must be a tuple")
        if not isinstance(self.affected_data_classifications, tuple):
            raise ValueError("affected_data_classifications must be a tuple")
        if not isinstance(self.regulatory_scopes, tuple):
            raise ValueError("regulatory_scopes must be a tuple")
        if not isinstance(self.contributing_factors, tuple):
            raise ValueError("contributing_factors must be a tuple")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "asset_id": self.asset_id,
            "blast_radius_level": self.blast_radius_level.value,
            "impact_score": round(self.impact_score, 2),
            "affected_applications": list(self.affected_applications),
            "affected_services": list(self.affected_services),
            "affected_business_functions": list(self.affected_business_functions),
            "affected_data_classifications": [d.value for d in self.affected_data_classifications],
            "criticality": self.criticality.value,
            "internet_exposed": self.internet_exposed,
            "regulatory_scopes": list(self.regulatory_scopes),
            "quantum_risk": self.quantum_risk.to_dict() if self.quantum_risk else None,
            "rationale": self.rationale,
            "contributing_factors": list(self.contributing_factors),
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
