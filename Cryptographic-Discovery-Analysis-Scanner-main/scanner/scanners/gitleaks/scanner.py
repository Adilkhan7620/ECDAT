"""Safe Gitleaks execution adapter for secret detection findings."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scanner.core.base_scanner import BaseScanner
from scanner.models.scan_result import ScannerResult, ScannerStatus
from scanner.scanners.gitleaks.parser import GitleaksParseError, GitleaksParser


class GitleaksScanner(BaseScanner):
    """Run Gitleaks secret detection against a directory.

    This adapter executes only a local Gitleaks binary in detection mode,
    captures native JSON output, and parses secret findings into ECDAT Findings
    with sensitive values redacted.
    """

    name = "gitleaks"
    default_executable = "gitleaks"

    def __init__(
        self,
        timeout_seconds: float = 300.0,
        executable: str | Path | None = None,
    ) -> None:
        """Configure a positive subprocess timeout and optional executable path."""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = timeout_seconds
        self._custom_executable = str(executable) if executable is not None else None
        self.parser = GitleaksParser()

    @property
    def executable(self) -> str:
        """Return the executable command or path.

        Priority order:
        1. Explicit constructor argument (`executable=...`)
        2. Environment variables (`GITLEAKS_PATH`, `ECDAT_GITLEAKS_PATH`, or `GITLEAKS_BINARY`)
        3. Default command name (`"gitleaks"`) searched on system `PATH`.
        """
        if self._custom_executable:
            return self._custom_executable
        env_executable = (
            os.environ.get("GITLEAKS_PATH")
            or os.environ.get("ECDAT_GITLEAKS_PATH")
            or os.environ.get("GITLEAKS_BINARY")
        )
        if env_executable:
            return env_executable
        return self.default_executable

    def build_command(self, target: Path) -> list[str]:
        """Build argv for Gitleaks JSON detection without invoking a shell."""
        return [
            self.executable,
            "detect",
            "--source",
            str(target),
            "--report-format",
            "json",
            "--no-git",
            "--exit-code",
            "0",
        ]

    def scan(self, target: Path) -> ScannerResult:
        """Execute Gitleaks safely and parse secret findings.

        Standard output is retained as ``raw_output`` and standard error as
        ``stderr`` in every execution outcome. No shell command is constructed.
        """
        if not target.is_dir():
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Target must be an existing local directory: {target}",
            )
        if not self.is_available():
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.TOOL_UNAVAILABLE,
                message="Gitleaks is not available on PATH.",
            )

        command = self.build_command(target)
        try:
            completed = subprocess.run(
                command,
                check=False,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Gitleaks timed out after {self.timeout_seconds} seconds.",
                raw_output=self.parser.sanitize_raw_output(_as_text(error.stdout)),
                stderr=_as_text(error.stderr),
                command=tuple(command),
            )
        except OSError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Gitleaks could not be started: {error}",
                command=tuple(command),
            )

        sanitized_raw_output = self.parser.sanitize_raw_output(completed.stdout)

        # Gitleaks exits 0 (no leaks) or 1 (leaks found / exit-code flag dependent) on clean run
        if completed.returncode not in (0, 1):
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Gitleaks process failed with exit code {completed.returncode}.",
                raw_output=sanitized_raw_output,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                command=tuple(command),
            )

        try:
            findings = self.parser.parse(completed.stdout, target)
        except GitleaksParseError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Gitleaks returned unparseable JSON: {error}",
                raw_output=sanitized_raw_output,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                command=tuple(command),
            )

        message = "Gitleaks scan completed."
        return ScannerResult(
            scanner=self.name,
            status=ScannerStatus.COMPLETED,
            message=message,
            findings=findings,
            raw_output=sanitized_raw_output,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            command=tuple(command),
        )


def _as_text(value: str | bytes | None) -> str | None:
    """Normalize timeout-captured streams to text without losing content."""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
