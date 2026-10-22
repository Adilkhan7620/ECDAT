"""Parser that converts Trivy JSON output into the shared ECDAT Finding contract."""

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


class TrivyParseError(ValueError):
    """Raised when Trivy output cannot be interpreted as a valid JSON report."""


class TrivyParser:
    """Normalize Trivy vulnerability detection results into ECDAT Findings."""

    def parse(self, raw_json: str, target: Path) -> tuple[Finding, ...]:
        """Parse Trivy JSON report into unreconciled ECDAT vulnerability findings."""
        if not raw_json or not raw_json.strip():
            return ()

        try:
            report = json.loads(raw_json)
        except json.JSONDecodeError as error:
            raise TrivyParseError(error.msg) from error

        if not isinstance(report, dict):
            raise TrivyParseError("top-level Trivy JSON output must be an object")

        results = report.get("Results")
        if results is None:
            return ()
        if not isinstance(results, list):
            raise TrivyParseError("Results field must be an array")

        findings: list[Finding] = []
        global_index = 0
        for result_idx, result_entry in enumerate(results):
            if not isinstance(result_entry, dict):
                continue

            target_path_raw = result_entry.get("Target")
            file_path = self._relative_file(target_path_raw, target)
            class_type = result_entry.get("Class")
            pkg_type = result_entry.get("Type")

            vulnerabilities = result_entry.get("Vulnerabilities")
            if not isinstance(vulnerabilities, list):
                continue

            for vuln_idx, vuln in enumerate(vulnerabilities):
                if not isinstance(vuln, dict):
                    continue
                finding = self._parse_vulnerability(
                    vuln,
                    result_idx=result_idx,
                    vuln_idx=vuln_idx,
                    global_idx=global_index,
                    file_path=file_path,
                    class_type=class_type,
                    pkg_type=pkg_type,
                )
                if finding is not None:
                    findings.append(finding)
                    global_index += 1

        return tuple(findings)

    def _parse_vulnerability(
        self,
        vuln: dict[str, object],
        result_idx: int,
        vuln_idx: int,
        global_idx: int,
        file_path: str | None,
        class_type: object,
        pkg_type: object,
    ) -> Finding | None:
        """Convert one Trivy vulnerability dictionary into an ECDAT Finding."""
        vuln_id = vuln.get("VulnerabilityID") or vuln.get("vulnerabilityID") or vuln.get("CVE")
        if not isinstance(vuln_id, str) or not vuln_id.strip():
            vuln_id = "UNKNOWN-VULN"

        pkg_name = vuln.get("PkgName") or vuln.get("pkgName")
        pkg_name_str = str(pkg_name) if isinstance(pkg_name, str) and pkg_name.strip() else "unknown-package"

        installed_ver = vuln.get("InstalledVersion") or vuln.get("installedVersion")
        installed_ver_str = (
            str(installed_ver) if isinstance(installed_ver, (str, int, float)) and str(installed_ver).strip() else "unknown"
        )

        fixed_ver = vuln.get("FixedVersion") or vuln.get("fixedVersion")
        fixed_ver_str = str(fixed_ver) if isinstance(fixed_ver, (str, int, float)) and str(fixed_ver).strip() else None

        severity = vuln.get("Severity") or vuln.get("severity")
        severity_str = str(severity) if isinstance(severity, str) and severity.strip() else "UNKNOWN"

        title = vuln.get("Title") or vuln.get("Description") or vuln.get("title")
        title_str = str(title) if isinstance(title, str) and title.strip() else None

        primary_url = vuln.get("PrimaryURL") or vuln.get("primaryURL")
        primary_url_str = str(primary_url) if isinstance(primary_url, str) and primary_url.strip() else None

        # Metadata gathering
        metadata: dict[str, object] = {
            "vulnerability_id": vuln_id,
            "package_name": pkg_name_str,
            "installed_version": installed_ver_str,
        }
        if fixed_ver_str:
            metadata["fixed_version"] = fixed_ver_str
        if title_str:
            metadata["title"] = title_str
        if primary_url_str:
            metadata["primary_url"] = primary_url_str
        if isinstance(class_type, str) and class_type.strip():
            metadata["class"] = class_type
        if isinstance(pkg_type, str) and pkg_type.strip():
            metadata["package_type"] = pkg_type

        message = f"Trivy vulnerability observation: {vuln_id} ({pkg_name_str}@{installed_ver_str})"

        # Deterministic UUID using vulnerability ID, package name, file path, index
        finding_id_key = f"trivy:{vuln_id}:{pkg_name_str}:{file_path}:{global_idx}"

        return Finding(
            finding_id=str(uuid5(NAMESPACE_URL, finding_id_key)),
            tool=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            evidence=ToolEvidence(
                message=message,
                original=vuln,
                raw_artifact="raw/trivy.json",
                raw_pointer=f"/Results/{result_idx}/Vulnerabilities/{vuln_idx}",
            ),
            metadata=metadata,
            file=file_path,
            line=None,
            severity=severity_str,
            rule=vuln_id,
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
