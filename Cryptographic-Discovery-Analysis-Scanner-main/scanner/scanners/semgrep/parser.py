"""Parser that converts Semgrep JSON into the shared ECDAT Finding contract."""

from __future__ import annotations

import json
from pathlib import Path, PurePath
from uuid import NAMESPACE_URL, uuid5

from shared.models import Finding, FindingCategory, FindingSource, ToolEvidence, ToolName


class SemgrepParseError(ValueError):
    """Raised when Semgrep output cannot be interpreted as its JSON report."""


class SemgrepParser:
    """Normalize only ECDAT-owned Semgrep crypto-discovery rule findings."""

    _RULE_MARKER = "ecdat.crypto."
    _ALGORITHMS = {
        "rsa": "RSA",
        "ecdsa": "ECDSA",
        "ecdh": "ECDH",
        "aes": "AES",
        "hashing": "hashing",
    }

    def parse(self, raw_json: str, target: Path) -> tuple[Finding, ...]:
        """Parse a Semgrep JSON document into unreconciled ECDAT findings.

        Unknown third-party Semgrep rules are excluded deliberately: the
        discovery engine only normalizes findings produced by ECDAT's focused
        crypto rule set in this phase.
        """
        try:
            report = json.loads(raw_json)
        except json.JSONDecodeError as error:
            raise SemgrepParseError(error.msg) from error
        if not isinstance(report, dict):
            raise SemgrepParseError("top-level JSON value must be an object")
        results = report.get("results", [])
        if not isinstance(results, list):
            raise SemgrepParseError("results must be an array")

        findings: list[Finding] = []
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            finding = self._parse_result(result, index, target)
            if finding is not None:
                findings.append(finding)
        return tuple(findings)

    def _parse_result(self, result: dict[str, object], index: int, target: Path) -> Finding | None:
        """Convert one ECDAT Semgrep result, preserving its native JSON object."""
        rule = result.get("check_id")
        if not isinstance(rule, str) or self._RULE_MARKER not in rule:
            return None
        # Semgrep prefixes local rule IDs with their configuration namespace
        # (for example ``scanner.scanners.semgrep.rules.ecdat.crypto.rsa``).
        # The native identifier remains intact in ``Finding.rule``.
        suffix = rule.rsplit(self._RULE_MARKER, maxsplit=1)[1]
        algorithm = self._ALGORITHMS.get(suffix)
        if algorithm is None:
            return None

        extra = result.get("extra")
        extra_data = extra if isinstance(extra, dict) else {}
        message = extra_data.get("message")
        if not isinstance(message, str) or not message.strip():
            message = f"ECDAT Semgrep crypto discovery: {algorithm}"

        raw_path = result.get("path")
        file = self._relative_file(raw_path, target)
        start = result.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        if not isinstance(line, int):
            line = None
        severity = extra_data.get("severity")
        if not isinstance(severity, str) or not severity.strip():
            severity = None

        metadata: dict[str, object] = {"language": self._language(extra_data)}
        if metadata["language"] is None:
            metadata.pop("language")
        return Finding(
            finding_id=str(uuid5(NAMESPACE_URL, f"semgrep:{rule}:{file}:{line}:{index}")),
            tool=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            evidence=ToolEvidence(
                message=message,
                original=result,
                raw_artifact="raw/semgrep.json",
                raw_pointer=f"/results/{index}",
            ),
            metadata=metadata,
            algorithm=algorithm,
            file=file,
            line=line,
            severity=severity,
            rule=rule,
        )

    @staticmethod
    def _relative_file(raw_path: object, target: Path) -> str | None:
        """Return a target-relative Semgrep result path when it is safe to do so."""
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

    @staticmethod
    def _language(extra: dict[str, object]) -> str | None:
        """Extract Semgrep's language field across supported JSON variations."""
        language = extra.get("language")
        if isinstance(language, str) and language:
            return language
        languages = extra.get("languages")
        if isinstance(languages, list) and languages and isinstance(languages[0], str):
            return languages[0]
        metadata = extra.get("metadata")
        if isinstance(metadata, dict):
            metadata_language = metadata.get("language")
            if isinstance(metadata_language, str) and metadata_language:
                return metadata_language
        return None
