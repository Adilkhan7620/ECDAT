"""Parser that converts Syft SBOM JSON output into the shared ECDAT Finding contract."""

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


class SyftParseError(ValueError):
    """Raised when Syft output cannot be interpreted as a valid JSON report."""


class SyftParser:
    """Normalize Syft software component/package findings into ECDAT Findings."""

    def parse(self, raw_json: str, target: Path) -> tuple[Finding, ...]:
        """Parse Syft JSON document into unreconciled ECDAT component findings."""
        if not raw_json or not raw_json.strip():
            return ()

        try:
            report = json.loads(raw_json)
        except json.JSONDecodeError as error:
            raise SyftParseError(error.msg) from error

        if not isinstance(report, dict):
            raise SyftParseError("top-level Syft JSON output must be an object")

        artifacts = report.get("artifacts")
        if artifacts is None:
            return ()
        if not isinstance(artifacts, list):
            raise SyftParseError("artifacts field must be an array")

        findings: list[Finding] = []
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                continue
            finding = self._parse_artifact(artifact, index, target)
            if finding is not None:
                findings.append(finding)
        return tuple(findings)

    def _parse_artifact(self, artifact: dict[str, object], index: int, target: Path) -> Finding | None:
        """Convert one Syft artifact dictionary into an ECDAT Finding."""
        name = artifact.get("name")
        if not isinstance(name, str) or not name.strip():
            return None

        version = artifact.get("version")
        version_str = str(version) if isinstance(version, (str, int, float)) and str(version).strip() else "unknown"

        pkg_type = artifact.get("type")
        pkg_type_str = str(pkg_type) if isinstance(pkg_type, str) and pkg_type.strip() else None

        purl = artifact.get("purl")
        purl_str = str(purl) if isinstance(purl, str) and purl.strip() else None

        # Extract first valid location relative file path if available
        file_path = self._extract_location(artifact.get("locations"), target)

        # Metadata gathering
        metadata: dict[str, object] = {
            "name": name,
            "version": version_str,
        }
        if pkg_type_str:
            metadata["package_type"] = pkg_type_str
        if purl_str:
            metadata["purl"] = purl_str

        language = artifact.get("language")
        if isinstance(language, str) and language.strip():
            metadata["language"] = language

        licenses = artifact.get("licenses")
        if isinstance(licenses, list) and licenses:
            metadata["licenses"] = licenses

        found_by = artifact.get("foundBy")
        if isinstance(found_by, str) and found_by.strip():
            metadata["found_by"] = found_by

        message = f"Syft component discovery: {name}@{version_str}"

        # Deterministic UUID using package identifier/PURL, version, file, index
        identifier_key = purl_str or name
        finding_id_key = f"syft:{identifier_key}:{version_str}:{file_path}:{index}"

        return Finding(
            finding_id=str(uuid5(NAMESPACE_URL, finding_id_key)),
            tool=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            evidence=ToolEvidence(
                message=message,
                original=artifact,
                raw_artifact="raw/syft.json",
                raw_pointer=f"/artifacts/{index}",
            ),
            metadata=metadata,
            file=file_path,
            line=None,
            severity=None,
            rule=None,
        )

    def _extract_location(self, locations: object, target: Path) -> str | None:
        """Extract first safe relative path from Syft locations array."""
        if not isinstance(locations, list) or not locations:
            return None

        for location in locations:
            if isinstance(location, dict):
                raw_path = location.get("path") or location.get("realpath")
                relative = self._relative_file(raw_path, target)
                if relative:
                    return relative
        return None

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
