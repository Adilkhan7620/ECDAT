"""Quantum Vulnerability Knowledge Base and Risk Assessment models for ECDAT."""

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
from scanner.models.classified_asset import EvidenceConfidence

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


class RiskLevel(str, Enum):
    """Controlled risk levels for ECDAT Quantum Risk Engine."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"


class QuantumVulnerabilityClass(str, Enum):
    """Quantum attack vulnerability taxonomy."""

    SHOR_VULNERABLE = "SHOR_VULNERABLE"
    GROVER_AFFECTED = "GROVER_AFFECTED"
    QUANTUM_RESISTANT = "QUANTUM_RESISTANT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class AlgorithmQuantumProfile:
    """Knowledge base entry for an algorithm's quantum vulnerability characteristics."""

    algorithm_name: str
    vulnerability_class: QuantumVulnerabilityClass
    primary_attack: str
    description: str
    impacts_confidentiality: bool = True
    impacts_integrity_authenticity: bool = True


class AlgorithmKnowledgeBase:
    """Deterministic knowledge base for cryptographic algorithm quantum vulnerability profiles."""

    _PROFILES: dict[str, AlgorithmQuantumProfile] = {
        "RSA": AlgorithmQuantumProfile(
            algorithm_name="RSA",
            vulnerability_class=QuantumVulnerabilityClass.SHOR_VULNERABLE,
            primary_attack="Shor's Algorithm",
            description="Asymmetric algorithm vulnerable to polynomial-time key recovery via Shor's algorithm.",
            impacts_confidentiality=True,
            impacts_integrity_authenticity=True,
        ),
        "ECDSA": AlgorithmQuantumProfile(
            algorithm_name="ECDSA",
            vulnerability_class=QuantumVulnerabilityClass.SHOR_VULNERABLE,
            primary_attack="Shor's Algorithm",
            description="Elliptic curve digital signature algorithm vulnerable to Shor's algorithm.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
        "ECDH": AlgorithmQuantumProfile(
            algorithm_name="ECDH",
            vulnerability_class=QuantumVulnerabilityClass.SHOR_VULNERABLE,
            primary_attack="Shor's Algorithm",
            description="Elliptic curve key exchange algorithm vulnerable to Shor's algorithm.",
            impacts_confidentiality=True,
            impacts_integrity_authenticity=False,
        ),
        "DH": AlgorithmQuantumProfile(
            algorithm_name="DH",
            vulnerability_class=QuantumVulnerabilityClass.SHOR_VULNERABLE,
            primary_attack="Shor's Algorithm",
            description="Diffie-Hellman key exchange vulnerable to Shor's algorithm.",
            impacts_confidentiality=True,
            impacts_integrity_authenticity=False,
        ),
        "Ed25519": AlgorithmQuantumProfile(
            algorithm_name="Ed25519",
            vulnerability_class=QuantumVulnerabilityClass.SHOR_VULNERABLE,
            primary_attack="Shor's Algorithm",
            description="Edwards-curve digital signature algorithm vulnerable to Shor's algorithm.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
        "Ed448": AlgorithmQuantumProfile(
            algorithm_name="Ed448",
            vulnerability_class=QuantumVulnerabilityClass.SHOR_VULNERABLE,
            primary_attack="Shor's Algorithm",
            description="Edwards-curve digital signature algorithm vulnerable to Shor's algorithm.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
        "AES": AlgorithmQuantumProfile(
            algorithm_name="AES",
            vulnerability_class=QuantumVulnerabilityClass.GROVER_AFFECTED,
            primary_attack="Grover's Algorithm",
            description="Symmetric encryption algorithm subject to Grover's quadratic search speedup (effective key length halved).",
            impacts_confidentiality=True,
            impacts_integrity_authenticity=False,
        ),
        "ChaCha20": AlgorithmQuantumProfile(
            algorithm_name="ChaCha20",
            vulnerability_class=QuantumVulnerabilityClass.GROVER_AFFECTED,
            primary_attack="Grover's Algorithm",
            description="Symmetric stream cipher subject to Grover's quadratic search speedup.",
            impacts_confidentiality=True,
            impacts_integrity_authenticity=False,
        ),
        "SHA-256": AlgorithmQuantumProfile(
            algorithm_name="SHA-256",
            vulnerability_class=QuantumVulnerabilityClass.GROVER_AFFECTED,
            primary_attack="Grover's / Brassard's Algorithm",
            description="Hash function subject to Grover's preimage attack speedup.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
        "SHA-384": AlgorithmQuantumProfile(
            algorithm_name="SHA-384",
            vulnerability_class=QuantumVulnerabilityClass.GROVER_AFFECTED,
            primary_attack="Grover's / Brassard's Algorithm",
            description="Hash function with strong 192-bit quantum security margin under Grover's algorithm.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
        "SHA-512": AlgorithmQuantumProfile(
            algorithm_name="SHA-512",
            vulnerability_class=QuantumVulnerabilityClass.GROVER_AFFECTED,
            primary_attack="Grover's / Brassard's Algorithm",
            description="Hash function with strong 256-bit quantum security margin under Grover's algorithm.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
        "SHA-1": AlgorithmQuantumProfile(
            algorithm_name="SHA-1",
            vulnerability_class=QuantumVulnerabilityClass.GROVER_AFFECTED,
            primary_attack="Classically Broken / Grover",
            description="Legacy hash function classically broken for collision resistance and affected by Grover's algorithm.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
        "MD5": AlgorithmQuantumProfile(
            algorithm_name="MD5",
            vulnerability_class=QuantumVulnerabilityClass.GROVER_AFFECTED,
            primary_attack="Classically Broken / Grover",
            description="Legacy hash function classically broken for collision resistance.",
            impacts_confidentiality=False,
            impacts_integrity_authenticity=True,
        ),
    }

    @classmethod
    def get_profile(cls, algorithm_name: str | None) -> AlgorithmQuantumProfile | None:
        """Return the quantum vulnerability profile for a given canonical algorithm name."""
        if not algorithm_name or not isinstance(algorithm_name, str):
            return None
        return cls._PROFILES.get(algorithm_name.strip())


@dataclass(frozen=True, slots=True)
class QuantumRiskAssessment:
    """Quantitative and qualitative quantum risk assessment for a classified asset."""

    asset_id: str
    risk_level: RiskLevel
    risk_score: float

    algorithm: str | None = None
    key_size: int | None = None
    usage: CryptoUsage | None = None

    data_lifetime_years: float | None = None
    migration_time_years: float | None = None
    years_until_crqc: float | None = None
    hndl_exposure: str = "UNKNOWN"

    rationale: str = ""
    contributing_factors: tuple[str, ...] = field(default_factory=tuple)
    confidence: EvidenceConfidence = EvidenceConfidence.UNKNOWN
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate quantum risk assessment invariants."""
        _require_non_empty(self.asset_id, "asset_id")
        if not isinstance(self.risk_level, RiskLevel):
            raise ValueError("risk_level must be a RiskLevel")
        if isinstance(self.risk_score, bool) or not isinstance(self.risk_score, (int, float)):
            raise ValueError("risk_score must be a numeric value between 0 and 100")
        if not 0.0 <= float(self.risk_score) <= 100.0:
            raise ValueError("risk_score must be between 0.0 and 100.0")
        if not isinstance(self.contributing_factors, tuple):
            raise ValueError("contributing_factors must be a tuple")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise ValueError("confidence must be an EvidenceConfidence")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary representation."""
        return {
            "asset_id": self.asset_id,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 2),
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "usage": self.usage.value if self.usage else None,
            "data_lifetime_years": self.data_lifetime_years,
            "migration_time_years": self.migration_time_years,
            "years_until_crqc": self.years_until_crqc,
            "hndl_exposure": self.hndl_exposure,
            "rationale": self.rationale,
            "contributing_factors": list(self.contributing_factors),
            "confidence": self.confidence.value,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
