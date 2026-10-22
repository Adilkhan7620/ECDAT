"""Orchestration for a local-path scanner run."""

from pathlib import Path
from typing import Iterable

from scanner.core.base_scanner import BaseScanner
from scanner.models.scan_result import ScannerResult


class ScanOrchestrator:
    """Run selected scanner adapters independently against one local target.

    This class intentionally returns per-tool results as-is. It performs no
    correlation, deduplication, risk analysis, or CBOM construction.
    """

    def __init__(self, scanners: Iterable[BaseScanner]) -> None:
        """Create an orchestrator with scanners keyed by their stable names."""
        self._scanners = {scanner.name: scanner for scanner in scanners}

    @property
    def scanner_names(self) -> tuple[str, ...]:
        """Return configured scanner names in registration order."""
        return tuple(self._scanners)

    def get_scanner(self, name: str) -> BaseScanner:
        """Return a configured adapter by name for diagnostics-only callers."""
        try:
            return self._scanners[name]
        except KeyError as error:
            raise ValueError(f"Unknown scanner: {name}") from error

    def scan(self, target: Path, selected: Iterable[str] | None = None) -> tuple[ScannerResult, ...]:
        """Run selected adapters sequentially and return their raw outcomes.

        A missing target is rejected before any scanner is selected. Scanner
        failures are represented by their own results in later implementations.
        """
        if not target.is_dir() and not target.is_file() and ":" not in str(target):
            raise ValueError(f"Target must be an existing local directory/file or endpoint: {target}")

        selected_names = tuple(selected) if selected is not None else self.scanner_names
        unknown = [name for name in selected_names if name not in self._scanners]
        if unknown:
            raise ValueError(f"Unknown scanner(s): {', '.join(unknown)}")

        return tuple(self._scanners[name].scan(target) for name in selected_names)
