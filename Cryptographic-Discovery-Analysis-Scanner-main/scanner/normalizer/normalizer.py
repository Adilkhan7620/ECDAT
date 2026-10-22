"""ECDAT Canonical Finding Normalization layer."""

from __future__ import annotations

from collections.abc import Iterable

from shared.models import Finding
from scanner.models.canonical_finding import CanonicalFinding
from scanner.models.scan_result import ScannerResult


class FindingNormalizer:
    """Normalizes scanner-specific Finding instances and ScannerResult batches into CanonicalFinding records."""

    def normalize_finding(self, finding: Finding) -> CanonicalFinding:
        """Normalize a single Finding instance into a CanonicalFinding."""
        return CanonicalFinding.from_finding(finding)

    def normalize(self, findings_or_results: Iterable[Finding | ScannerResult] | Finding | ScannerResult) -> tuple[CanonicalFinding, ...]:
        """Normalize findings or scanner results into canonical ECDAT findings in input order.

        Accepts:
        - a single Finding or ScannerResult object
        - an iterable of Finding objects
        - an iterable of ScannerResult objects
        - a mix of Finding and ScannerResult objects
        """
        if isinstance(findings_or_results, Finding):
            return (self.normalize_finding(findings_or_results),)

        if isinstance(findings_or_results, ScannerResult):
            return tuple(self.normalize_finding(f) for f in findings_or_results.findings)

        canonical: list[CanonicalFinding] = []
        for item in findings_or_results:
            if isinstance(item, Finding):
                canonical.append(self.normalize_finding(item))
            elif isinstance(item, ScannerResult):
                for f in item.findings:
                    canonical.append(self.normalize_finding(f))
            elif isinstance(item, CanonicalFinding):
                canonical.append(item)
            else:
                raise TypeError(f"Cannot normalize object of type {type(item).__name__}")

        return tuple(canonical)
