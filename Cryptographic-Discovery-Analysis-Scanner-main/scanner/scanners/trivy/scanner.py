"""Safe Trivy execution adapter for vulnerability detection findings."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scanner.core.base_scanner import BaseScanner
from scanner.models.scan_result import ScannerResult, ScannerStatus
from scanner.scanners.trivy.parser import TrivyParseError, TrivyParser


class TrivyScanner(BaseScanner):
    """Run Trivy filesystem vulnerability detection against a directory.

    This adapter executes Trivy in filesystem mode, captures native JSON output,
    and parses vulnerability findings into ECDAT Findings.
    """

    name = "trivy"
    default_executable = "trivy"

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
        self.parser = TrivyParser()

    @property
    def executable(self) -> str:
        """Return the executable command or path.

        Priority order:
        1. Explicit constructor argument (`executable=...`)
        2. Environment variables (`TRIVY_PATH`, `ECDAT_TRIVY_PATH`, or `TRIVY_BINARY`)
        3. Default command name (`"trivy"`) searched on system `PATH`.
        """
        if self._custom_executable:
            return self._custom_executable
        env_executable = (
            os.environ.get("TRIVY_PATH")
            or os.environ.get("ECDAT_TRIVY_PATH")
            or os.environ.get("TRIVY_BINARY")
        )
        if env_executable:
            return env_executable
        return self.default_executable

    def build_command(self, target: Path) -> list[str]:
        """Build argv for Trivy JSON filesystem scan without invoking a shell."""
        return [
            self.executable,
            "fs",
            "--format",
            "json",
            str(target),
        ]

    def scan(self, target: Path) -> ScannerResult:
        """Execute Trivy safely and parse vulnerability findings.

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
                message="Trivy is not available on PATH.",
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
                message=f"Trivy timed out after {self.timeout_seconds} seconds.",
                raw_output=_as_text(error.stdout),
                stderr=_as_text(error.stderr),
                command=tuple(command),
            )
        except OSError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Trivy could not be started: {error}",
                command=tuple(command),
            )

        if completed.returncode != 0:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Trivy process failed with exit code {completed.returncode}.",
                raw_output=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                command=tuple(command),
            )

        try:
            findings = self.parser.parse(completed.stdout, target)
        except TrivyParseError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Trivy returned unparseable JSON: {error}",
                raw_output=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                command=tuple(command),
            )

        message = "Trivy scan completed."
        return ScannerResult(
            scanner=self.name,
            status=ScannerStatus.COMPLETED,
            message=message,
            findings=findings,
            raw_output=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            command=tuple(command),
        )


def _as_text(value: str | bytes | None) -> str | None:
    """Normalize timeout-captured streams to text without losing content."""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
