"""Canonical finding data model for ECDAT correlation engine and reporting."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from shared.models.finding import (
    CryptoUsage,
    Finding,
    FindingCategory,
    FindingSource,
    ToolEvidence,
    ToolName,
    _require_non_empty,
    _validate_json,
)

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class CanonicalFinding:
    """Canonical ECDAT finding representation normalized across all discovery tools.

    Provides a unified model for Semgrep, Gitleaks, Syft, Trivy, and OpenSSL
    discoveries before cross-scanner correlation and risk assessment.
    """

    # Identity / Provenance
    finding_id: str
    scanner: ToolName
    category: FindingCategory
    source: FindingSource

    # Finding Information
    title: str | None = None
    finding_type: str | None = None
    description: str | None = None
    severity: str | None = None
    confidence: float | None = None

    # Cryptographic Information
    algorithm: str | None = None
    key_size: int | None = None
    usage: CryptoUsage | None = None

    # Location
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None

    # Dependency Information
    package_name: str | None = None
    package_version: str | None = None
    package_type: str | None = None

    # Vulnerability Information
    vulnerability_id: str | None = None
    fixed_version: str | None = None

    # Certificate / TLS Information
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    san: str | None = None
    protocol: str | None = None
    cipher: str | None = None

    # Evidence
    evidence: ToolEvidence | None = None
    raw_artifact: str | None = None

    # Scanner-specific metadata/extensions
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate canonical finding invariants."""
        _require_non_empty(self.finding_id, "finding_id")
        if not isinstance(self.scanner, ToolName):
            raise ValueError("scanner must be a ToolName")
        if not isinstance(self.category, FindingCategory):
            raise ValueError("category must be a FindingCategory")
        if not isinstance(self.source, FindingSource):
            raise ValueError("source must be a FindingSource")

        if self.evidence is not None and not isinstance(self.evidence, ToolEvidence):
            raise ValueError("evidence must be a ToolEvidence when provided")

        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

        for field_name, value in (
            ("title", self.title),
            ("finding_type", self.finding_type),
            ("description", self.description),
            ("severity", self.severity),
            ("algorithm", self.algorithm),
            ("file", self.file),
            ("package_name", self.package_name),
            ("package_version", self.package_version),
            ("package_type", self.package_type),
            ("vulnerability_id", self.vulnerability_id),
            ("fixed_version", self.fixed_version),
            ("subject", self.subject),
            ("issuer", self.issuer),
            ("serial", self.serial),
            ("valid_from", self.valid_from),
            ("valid_until", self.valid_until),
            ("signature_algorithm", self.signature_algorithm),
            ("public_key_algorithm", self.public_key_algorithm),
            ("san", self.san),
            ("protocol", self.protocol),
            ("cipher", self.cipher),
            ("raw_artifact", self.raw_artifact),
        ):
            if value is not None:
                _require_non_empty(value, field_name)

        if self.key_size is not None and (isinstance(self.key_size, bool) or not isinstance(self.key_size, int) or self.key_size <= 0):
            raise ValueError("key_size must be a positive integer when provided")

        if self.line_start is not None and (isinstance(self.line_start, bool) or not isinstance(self.line_start, int) or self.line_start < 1):
            raise ValueError("line_start must be a positive integer when provided")

        if self.line_end is not None and (isinstance(self.line_end, bool) or not isinstance(self.line_end, int) or self.line_end < 1):
            raise ValueError("line_end must be a positive integer when provided")

        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise ValueError("confidence must be a number between 0 and 1 when provided")
            if not 0.0 <= float(self.confidence) <= 1.0:
                raise ValueError("confidence must be between 0 and 1 when provided")

    @classmethod
    def from_finding(cls, finding: Finding) -> CanonicalFinding:
        """Construct a CanonicalFinding from a scanner-produced Finding model."""
        metadata = dict(finding.metadata)

        # Common location fields
        file_path = finding.file
        line_start = finding.line
        # Read metadata without mutating original metadata dictionary
        # Location fields
        file_path = finding.file
        line_start = finding.line
        line_end_val = metadata.get("line_end")
        line_end = line_end_val if isinstance(line_end_val, int) and line_end_val >= 1 else None

        # Title and Description
        title_val = metadata.get("title")
        title = title_val if isinstance(title_val, str) and title_val.strip() else None

        description = finding.evidence.message if finding.evidence else None
        if not description and title:
            description = title

        finding_type = finding.rule or finding.category.value

        # Dependency fields (Syft / Trivy)
        package_name_val = metadata.get("package_name") or metadata.get("name") or metadata.get("pkgName")
        package_name = package_name_val if isinstance(package_name_val, str) and package_name_val.strip() else None

        package_version_val = metadata.get("package_version") or metadata.get("installed_version") or metadata.get("version")
        package_version = package_version_val if isinstance(package_version_val, (str, int, float)) and str(package_version_val).strip() else None
        if package_version:
            package_version = str(package_version)

        package_type_val = metadata.get("package_type")
        package_type = package_type_val if isinstance(package_type_val, str) and package_type_val.strip() else None

        # Vulnerability fields (Trivy)
        vulnerability_id_val = metadata.get("vulnerability_id") or (finding.rule if finding.category == FindingCategory.VULNERABILITY else None)
        vulnerability_id = vulnerability_id_val if isinstance(vulnerability_id_val, str) and vulnerability_id_val.strip() else None

        fixed_version_val = metadata.get("fixed_version")
        fixed_version = fixed_version_val if isinstance(fixed_version_val, (str, int, float)) and str(fixed_version_val).strip() else None
        if fixed_version:
            fixed_version = str(fixed_version)

        # Certificate / TLS fields (OpenSSL)
        subject_val = metadata.get("subject")
        subject = subject_val if isinstance(subject_val, str) and subject_val.strip() else None

        issuer_val = metadata.get("issuer")
        issuer = issuer_val if isinstance(issuer_val, str) and issuer_val.strip() else None

        serial_val = metadata.get("serial_number") or metadata.get("serial")
        serial = serial_val if isinstance(serial_val, str) and serial_val.strip() else None

        valid_from_val = metadata.get("validity_not_before") or metadata.get("valid_from")
        valid_from = valid_from_val if isinstance(valid_from_val, str) and valid_from_val.strip() else None

        valid_until_val = metadata.get("validity_not_after") or metadata.get("valid_until")
        valid_until = valid_until_val if isinstance(valid_until_val, str) and valid_until_val.strip() else None

        sig_alg_val = metadata.get("signature_algorithm")
        sig_alg = sig_alg_val if isinstance(sig_alg_val, str) and sig_alg_val.strip() else None

        pubkey_alg_val = metadata.get("public_key_algorithm")
        pubkey_alg = pubkey_alg_val if isinstance(pubkey_alg_val, str) and pubkey_alg_val.strip() else None

        san_val = metadata.get("sans") or metadata.get("san")
        san = san_val if isinstance(san_val, str) and san_val.strip() else None

        protocol_val = metadata.get("protocol")
        protocol = protocol_val if isinstance(protocol_val, str) and protocol_val.strip() else None

        cipher_val = metadata.get("cipher")
        cipher = cipher_val if isinstance(cipher_val, str) and cipher_val.strip() else None

        raw_artifact = finding.evidence.raw_artifact if finding.evidence else None

        return cls(
            finding_id=finding.finding_id,
            scanner=finding.tool,
            category=finding.category,
            source=finding.source,
            title=title,
            finding_type=finding_type,
            description=description,
            severity=finding.severity,
            confidence=finding.confidence,
            algorithm=finding.algorithm,
            key_size=finding.key_size,
            usage=finding.usage,
            file=file_path,
            line_start=line_start,
            line_end=line_end,
            package_name=package_name,
            package_version=package_version,
            package_type=package_type,
            vulnerability_id=vulnerability_id,
            fixed_version=fixed_version,
            subject=subject,
            issuer=issuer,
            serial=serial,
            valid_from=valid_from,
            valid_until=valid_until,
            signature_algorithm=sig_alg,
            public_key_algorithm=pubkey_alg,
            san=san,
            protocol=protocol,
            cipher=cipher,
            evidence=finding.evidence,
            raw_artifact=raw_artifact,
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of CanonicalFinding."""
        return {
            "finding_id": self.finding_id,
            "scanner": self.scanner.value,
            "category": self.category.value,
            "source": self.source.value,
            "title": self.title,
            "finding_type": self.finding_type,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "usage": self.usage.value if self.usage else None,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "package_type": self.package_type,
            "vulnerability_id": self.vulnerability_id,
            "fixed_version": self.fixed_version,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "san": self.san,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "raw_artifact": self.raw_artifact,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
