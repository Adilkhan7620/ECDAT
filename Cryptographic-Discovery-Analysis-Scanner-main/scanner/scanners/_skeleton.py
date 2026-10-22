"""Reusable controlled-result behavior for scanner skeleton adapters."""

from pathlib import Path

from scanner.core.base_scanner import BaseScanner
from scanner.models.scan_result import ScannerResult, ScannerStatus


class SkeletonScanner(BaseScanner):
    """Base adapter that reports availability without running a native tool."""

    name: str
    executable: str

    def scan(self, target: Path) -> ScannerResult:
        """Return a stable skeleton result and never invoke an external tool."""
        if not self.is_available():
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.TOOL_UNAVAILABLE,
                message=(
                    f"{self.executable!r} is not available on PATH; "
                    "scanner execution is not implemented in this phase."
                ),
            )

        return ScannerResult(
            scanner=self.name,
            status=ScannerStatus.NOT_IMPLEMENTED,
            message=(
                f"{self.name} was selected for {target}; native execution and "
                "parsing are not implemented in this skeleton."
            ),
        )
