"""Shared, scanner-independent ECDAT Finding data contract."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePath
from typing import TypeAlias

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]


class ToolName(str, Enum):
    """Discovery tools within the currently documented ECDAT scope."""

    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"
    SYFT = "syft"
    TRIVY = "trivy"
    OPENSSL = "openssl"


class FindingCategory(str, Enum):
    """Evidence categories emitted before cross-tool correlation."""

    CRYPTO_API = "crypto_api"
    SECRET = "secret"
    COMPONENT = "component"
    VULNERABILITY = "vulnerability"
    CERTIFICATE = "certificate"
    PUBLIC_KEY = "public_key"


class FindingSource(str, Enum):
    """Target material from which the scanner observed the finding."""

    SOURCE_CODE = "source_code"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    CERTIFICATE_FILE = "certificate_file"
    PUBLIC_KEY_FILE = "public_key_file"
    SECRET_STORE = "secret_store"


class CryptoUsage(str, Enum):
    """Optional scanner-observed cryptographic usage hint."""

    ENCRYPTION = "encryption"
    KEY_EXCHANGE = "key_exchange"
    DIGITAL_SIGNATURE = "digital_signature"
    HASHING = "hashing"
    MESSAGE_AUTHENTICATION = "message_authentication"
    KEY_DERIVATION = "key_derivation"
    UNKNOWN = "unknown"


def _validate_json(value: JsonValue, field_name: str) -> None:
    """Reject metadata/evidence values that cannot be represented as JSON."""
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name} must contain only JSON-serializable values") from error


def _require_non_empty(value: str, field_name: str) -> None:
    """Require a meaningful string identifier or evidence message."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class ToolEvidence:
    """Original evidence retained from one native scanner result.

    ``original`` stores the tool-provided evidence structure unchanged where
    possible. It permits tool-specific fields without leaking those fields into
    the common Finding contract. ``raw_artifact`` and ``raw_pointer`` locate a
    preserved native report when one is stored by a later execution layer.
    """

    message: str
    original: dict[str, JsonValue] = field(default_factory=dict)
    raw_artifact: str | None = None
    raw_pointer: str | None = None

    def __post_init__(self) -> None:
        """Validate evidence without interpreting native scanner semantics."""
        _require_non_empty(self.message, "evidence.message")
        if not isinstance(self.original, dict):
            raise ValueError("evidence.original must be a JSON object")
        _validate_json(self.original, "evidence.original")
        for field_name, value in (("evidence.raw_artifact", self.raw_artifact), ("evidence.raw_pointer", self.raw_pointer)):
            if value is not None:
                _require_non_empty(value, field_name)

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a JSON-compatible evidence object."""
        return {
            "message": self.message,
            "original": self.original,
            "raw_artifact": self.raw_artifact,
            "raw_pointer": self.raw_pointer,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """One raw/normalized cryptographic discovery, not a final CBOM asset.

    Required fields are ``finding_id``, ``tool``, ``category``, ``source``,
    ``evidence``, and ``metadata``. All cryptographic details are optional
    because not every scanner can observe them. ``confidence`` is strictly the
    source tool's confidence when it provides one; it is not a future
    Correlation Engine confidence score.
    """

    finding_id: str
    tool: ToolName
    category: FindingCategory
    source: FindingSource
    evidence: ToolEvidence
    metadata: dict[str, JsonValue]
    algorithm: str | None = None
    key_size: int | None = None
    usage: CryptoUsage | None = None
    file: str | None = None
    line: int | None = None
    confidence: float | None = None
    severity: str | None = None
    rule: str | None = None

    def __post_init__(self) -> None:
        """Validate field shape while leaving scanner-specific facts untouched."""
        _require_non_empty(self.finding_id, "finding_id")
        if not isinstance(self.tool, ToolName):
            raise ValueError("tool must be a ToolName")
        if not isinstance(self.category, FindingCategory):
            raise ValueError("category must be a FindingCategory")
        if not isinstance(self.source, FindingSource):
            raise ValueError("source must be a FindingSource")
        if not isinstance(self.evidence, ToolEvidence):
            raise ValueError("evidence must be a ToolEvidence")
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_json(self.metadata, "metadata")

        for field_name, value in (
            ("algorithm", self.algorithm),
            ("severity", self.severity),
            ("rule", self.rule),
        ):
            if value is not None:
                _require_non_empty(value, field_name)
        if self.key_size is not None and (isinstance(self.key_size, bool) or self.key_size <= 0):
            raise ValueError("key_size must be a positive integer when provided")
        if self.key_size is not None and not isinstance(self.key_size, int):
            raise ValueError("key_size must be an integer when provided")
        if self.usage is not None and not isinstance(self.usage, CryptoUsage):
            raise ValueError("usage must be a CryptoUsage when provided")
        if self.file is not None:
            _require_non_empty(self.file, "file")
            file_path = PurePath(self.file)
            if file_path.is_absolute() or ".." in file_path.parts:
                raise ValueError("file must be a relative path within the scan target")
        if self.line is not None and (isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1):
            raise ValueError("line must be a positive integer when provided")
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise ValueError("confidence must be a number between 0 and 1 when provided")
            if not 0.0 <= float(self.confidence) <= 1.0:
                raise ValueError("confidence must be between 0 and 1 when provided")

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the stable JSON representation shared with future modules."""
        return {
            "finding_id": self.finding_id,
            "tool": self.tool.value,
            "category": self.category.value,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "usage": self.usage.value if self.usage is not None else None,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence.to_dict(),
            "confidence": self.confidence,
            "severity": self.severity,
            "rule": self.rule,
            "source": self.source.value,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize this contract as deterministic JSON."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
