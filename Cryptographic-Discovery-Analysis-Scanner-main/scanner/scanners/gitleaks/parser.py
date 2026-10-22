"""Parser that converts Gitleaks JSON output into the shared ECDAT Finding contract."""

from __future__ import annotations

import json
from pathlib import Path, PurePath
from uuid import NAMESPACE_URL, uuid5

from shared.models import (
    Finding,
    FindingCategory,
    FindingSource,
    ToolEvidence,
    ToolName,
)


class GitleaksParseError(ValueError):
    """Raised when Gitleaks output cannot be interpreted as a valid report."""


class GitleaksParser:
    """Normalize Gitleaks secret detection results into ECDAT Findings."""

    @staticmethod
    def sanitize_raw_output(raw_json: str | None) -> str | None:
        """Sanitize raw Gitleaks output by replacing Secret and Match values with [REDACTED].

        This prevents secrets from leaking through in-memory ScannerResult
        objects, CLI output summaries, API payloads, or standard logs while
        preserving all non-sensitive evidence metadata.
        """
        if not raw_json or not raw_json.strip():
            return raw_json

        try:
            data = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            return raw_json

        if not isinstance(data, list):
            return raw_json

        sanitized_list: list[dict[str, object]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            sanitized_item: dict[str, object] = {}
            for key, value in item.items():
                if key in ("Secret", "Match", "secret", "match") and value is not None:
                    sanitized_item[key] = "[REDACTED]"
                else:
                    sanitized_item[key] = value
            sanitized_list.append(sanitized_item)

        return json.dumps(sanitized_list)

    def parse(self, raw_json: str, target: Path) -> tuple[Finding, ...]:
        """Parse Gitleaks JSON document into unreconciled ECDAT findings.

        Raw secret values and matched content are redacted before storing in
        evidence to avoid leaking credentials.
        """
        if not raw_json or not raw_json.strip():
            return ()

        try:
            results = json.loads(raw_json)
        except json.JSONDecodeError as error:
            raise GitleaksParseError(error.msg) from error

        if not isinstance(results, list):
            raise GitleaksParseError("top-level JSON value must be an array of findings")

        findings: list[Finding] = []
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            finding = self._parse_result(result, index, target)
            if finding is not None:
                findings.append(finding)
        return tuple(findings)

    def _parse_result(self, result: dict[str, object], index: int, target: Path) -> Finding | None:
        """Convert one Gitleaks finding record into an ECDAT Finding."""
        rule_id = result.get("RuleID") or result.get("ruleID") or result.get("RuleId")
        if not isinstance(rule_id, str) or not rule_id.strip():
            rule_id = "gitleaks-secret"

        description = result.get("Description")
        if not isinstance(description, str) or not description.strip():
            description = f"Gitleaks secret observation: {rule_id}"

        # Redact raw secret values from the stored evidence dictionary
        redacted_original: dict[str, object] = {}
        for key, value in result.items():
            if key in ("Secret", "Match", "secret", "match"):
                redacted_original[key] = "[REDACTED]"
            else:
                redacted_original[key] = value

        raw_file = result.get("File") or result.get("file")
        file_path = self._relative_file(raw_file, target)

        start_line = result.get("StartLine") or result.get("startLine")
        line = start_line if isinstance(start_line, int) and start_line >= 1 else None

        # Non-sensitive metadata extraction
        metadata: dict[str, object] = {}
        fingerprint = result.get("Fingerprint") or result.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint.strip():
            metadata["fingerprint"] = fingerprint
        entropy = result.get("Entropy") or result.get("entropy")
        if isinstance(entropy, (int, float)):
            metadata["entropy"] = float(entropy)

        severity = result.get("Severity")
        severity_str = str(severity) if isinstance(severity, str) and severity.strip() else "HIGH"

        return Finding(
            finding_id=str(uuid5(NAMESPACE_URL, f"gitleaks:{rule_id}:{file_path}:{line}:{index}")),
            tool=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            evidence=ToolEvidence(
                message=description,
                original=redacted_original,
                raw_artifact="raw/gitleaks.json",
                raw_pointer=f"/{index}",
            ),
            metadata=metadata,
            file=file_path,
            line=line,
            severity=severity_str,
            rule=rule_id,
        )

    @staticmethod
    def _relative_file(raw_path: object, target: Path) -> str | None:
        """Return a target-relative file path when safe to do so."""
        if not isinstance(raw_path, str) or not raw_path:
            return None
        candidate = Path(raw_path)
        if candidate.is_absolute():
            try:
                return str(candidate.resolve().relative_to(target.resolve()))
            except ValueError:
                return None
        relative = PurePath(raw_path)
        if ".." in relative.parts:
            return None
        return str(relative)
