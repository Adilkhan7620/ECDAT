"""Scanner outcome types used by adapters and the orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from scanner.models.finding import Finding


class ScannerStatus(str, Enum):
    """Controlled states for an independently run scanner."""

    NOT_IMPLEMENTED = "not_implemented"
    TOOL_UNAVAILABLE = "tool_unavailable"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ScannerResult:
    """Result produced by one scanner adapter.

    ``findings`` remains empty in the skeleton because native command execution
    and parser implementations are intentionally deferred.
    """

    scanner: str
    status: ScannerStatus
    message: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    raw_output: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    command: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable result."""
        return {
            "scanner": self.scanner,
            "status": self.status.value,
            "message": self.message,
            "findings": [finding.to_dict() for finding in self.findings],
            "raw_output": self.raw_output,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "command": list(self.command),
        }
