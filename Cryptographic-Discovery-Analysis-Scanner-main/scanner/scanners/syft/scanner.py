"""Safe Syft execution adapter for software component & SBOM discovery."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scanner.core.base_scanner import BaseScanner
from scanner.models.scan_result import ScannerResult, ScannerStatus
from scanner.scanners.syft.parser import SyftParseError, SyftParser


class SyftScanner(BaseScanner):
    """Run Syft SBOM/package discovery against a directory.

    This adapter executes Syft to generate a machine-readable JSON software
    bill of materials (SBOM) and parses software components into ECDAT Findings.
    """

    name = "syft"
    default_executable = "syft"

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
        self.parser = SyftParser()

    @property
    def executable(self) -> str:
        """Return the executable command or path.

        Priority order:
        1. Explicit constructor argument (`executable=...`)
        2. Environment variables (`SYFT_PATH`, `ECDAT_SYFT_PATH`, or `SYFT_BINARY`)
        3. Default command name (`"syft"`) searched on system `PATH`.
        """
        if self._custom_executable:
            return self._custom_executable
        env_executable = (
            os.environ.get("SYFT_PATH")
            or os.environ.get("ECDAT_SYFT_PATH")
            or os.environ.get("SYFT_BINARY")
        )
        if env_executable:
            return env_executable
        return self.default_executable

    def build_command(self, target: Path) -> list[str]:
        """Build argv for Syft JSON directory scan without invoking a shell."""
        return [
            self.executable,
            f"dir:{target}",
            "-o",
            "json",
        ]

    def scan(self, target: Path) -> ScannerResult:
        """Execute Syft safely and parse component findings.

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
                message="Syft is not available on PATH.",
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
                message=f"Syft timed out after {self.timeout_seconds} seconds.",
                raw_output=_as_text(error.stdout),
                stderr=_as_text(error.stderr),
                command=tuple(command),
            )
        except OSError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Syft could not be started: {error}",
                command=tuple(command),
            )

        if completed.returncode != 0:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Syft process failed with exit code {completed.returncode}.",
                raw_output=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                command=tuple(command),
            )

        try:
            findings = self.parser.parse(completed.stdout, target)
        except SyftParseError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Syft returned unparseable JSON: {error}",
                raw_output=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                command=tuple(command),
            )

        message = "Syft scan completed."
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
