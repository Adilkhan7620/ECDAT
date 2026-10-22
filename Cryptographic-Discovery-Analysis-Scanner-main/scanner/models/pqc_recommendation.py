"""PQC Knowledge Base, Migration Strategy, Priority, and Recommendation models for ECDAT."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias

from shared.models.finding import (
    CryptoUsage,
    _require_non_empty,
    _validate_json,
)
from scanner.models.blast_radius import BlastRadiusLevel
from scanner.models.quantum_risk import RiskLevel

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


class MigrationStrategy(str, Enum):
    """PQC migration strategy options."""

    DIRECT_PQC = "DIRECT_PQC"
    HYBRID = "HYBRID"
    RETAIN_MONITOR = "RETAIN_MONITOR"
    DEPRECATE = "DEPRECATE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class MigrationPriority(str, Enum):
    """PQC transition priority levels."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    MONITOR = "MONITOR"


class MigrationEffort(str, Enum):
    """Estimated engineering migration effort categories."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class PqcAlgorithmProfile:
    """Knowledge base entry for a standardized PQC algorithm/family."""

    algorithm_name: str
    nist_standard: str
    purpose: str
    supported_use_cases: tuple[CryptoUsage, ...]
    classical_counterpart: str
    transition_considerations: str


class PqcKnowledgeBase:
    """Deterministic knowledge base for standardized Post-Quantum Cryptography algorithms."""

    _PROFILES: dict[str, PqcAlgorithmProfile] = {
        "ML-KEM": PqcAlgorithmProfile(
            algorithm_name="ML-KEM",
            nist_standard="FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)",
            purpose="Key establishment / Key encapsulation",
            supported_use_cases=(CryptoUsage.KEY_EXCHANGE, CryptoUsage.ENCRYPTION),
            classical_counterpart="RSA / ECDH / DH",
            transition_considerations="Requires hybrid key exchange transition mode for TLS and key establishment protocol compatibility.",
        ),
        "ML-DSA": PqcAlgorithmProfile(
            algorithm_name="ML-DSA",
            nist_standard="FIPS 204 (Module-Lattice-Based Digital Signature Algorithm)",
            purpose="Digital signatures and authentication",
            supported_use_cases=(CryptoUsage.DIGITAL_SIGNATURE,),
            classical_counterpart="RSA / ECDSA / Ed25519 / Ed448",
            transition_considerations="Larger public key and signature sizes compared to ECC; requires PKI certificate chain and software dependency updates.",
        ),
        "SLH-DSA": PqcAlgorithmProfile(
            algorithm_name="SLH-DSA",
            nist_standard="FIPS 205 (Stateless Hash-Based Digital Signature Algorithm)",
            purpose="Stateless hash-based digital signatures",
            supported_use_cases=(CryptoUsage.DIGITAL_SIGNATURE,),
            classical_counterpart="RSA / ECDSA",
            transition_considerations="Conservative security relying strictly on hash functions; larger signature sizes and slower signature generation.",
        ),
    }

    @classmethod
    def get_profile(cls, name: str) -> PqcAlgorithmProfile | None:
        """Return standardized PQC algorithm profile by name."""
        return cls._PROFILES.get(name)


@dataclass(frozen=True, slots=True)
class PqcMigrationRecommendation:
    """Actionable PQC migration recommendation for a discovery asset."""

    asset_id: str
    current_algorithm: str | None
    current_usage: CryptoUsage | None
    current_key_size: int | None

    recommended_algorithm: str | None
    recommended_family: str | None
    migration_strategy: MigrationStrategy
    migration_priority: MigrationPriority
    migration_effort: MigrationEffort

    rationale: str
    compatibility_considerations: str = ""
    hndl_consideration: str = ""

    quantum_risk_level: RiskLevel = RiskLevel.UNKNOWN
    blast_radius_level: BlastRadiusLevel = BlastRadiusLevel.UNKNOWN

    supporting_finding_ids: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate recommendation invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        if not isinstance(self.migration_strategy, MigrationStrategy):
            raise ValueError("migration_strategy must be a MigrationStrategy")
        if not isinstance(self.migration_priority, MigrationPriority):
            raise ValueError("migration_priority must be a MigrationPriority")
        if not isinstance(self.migration_effort, MigrationEffort):
            raise ValueError("migration_effort must be a MigrationEffort")
        if not isinstance(self.quantum_risk_level, RiskLevel):
            raise ValueError("quantum_risk_level must be a RiskLevel")
        if not isinstance(self.blast_radius_level, BlastRadiusLevel):
            raise ValueError("blast_radius_level must be a BlastRadiusLevel")
        if not isinstance(self.supporting_finding_ids, tuple):
            raise ValueError("supporting_finding_ids must be a tuple")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "asset_id": self.asset_id,
            "current_algorithm": self.current_algorithm,
            "current_usage": self.current_usage.value if self.current_usage else None,
            "current_key_size": self.current_key_size,
            "recommended_algorithm": self.recommended_algorithm,
            "recommended_family": self.recommended_family,
            "migration_strategy": self.migration_strategy.value,
            "migration_priority": self.migration_priority.value,
            "migration_effort": self.migration_effort.value,
            "rationale": self.rationale,
            "compatibility_considerations": self.compatibility_considerations,
            "hndl_consideration": self.hndl_consideration,
            "quantum_risk_level": self.quantum_risk_level.value,
            "blast_radius_level": self.blast_radius_level.value,
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
