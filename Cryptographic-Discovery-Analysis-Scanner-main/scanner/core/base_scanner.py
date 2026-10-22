"""Base interface implemented by all ECDAT scanner adapters."""

from abc import ABC, abstractmethod
from pathlib import Path

from scanner.models.scan_result import ScannerResult


class BaseScanner(ABC):
    """Contract for an independently runnable discovery-tool adapter.

    Adapters are responsible for their own tool-specific execution and parsing.
    The skeleton adapters only report availability; they do not invoke tools.
    """

    name: str
    executable: str

    @abstractmethod
    def scan(self, target: Path) -> ScannerResult:
        """Scan ``target`` and return its isolated scanner result.

        Implementations must never raise solely because the external executable
        is unavailable. They should return a controlled result instead.
        """

    def is_available(self) -> bool:
        """Return whether the scanner's native executable is on ``PATH``."""
        from shutil import which

        return which(self.executable) is not None

