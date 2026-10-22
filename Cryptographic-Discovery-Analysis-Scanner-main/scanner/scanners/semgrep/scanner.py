"""Safe Semgrep execution adapter for ECDAT crypto discovery rules."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from scanner.core.base_scanner import BaseScanner
from scanner.models.scan_result import ScannerResult, ScannerStatus
from scanner.scanners.semgrep.parser import SemgrepParseError, SemgrepParser


class SemgrepScanner(BaseScanner):
    """Run Semgrep's local ECDAT crypto-discovery rule set against a directory.

    This adapter executes only a local Semgrep binary and a version-controlled
    local rule file. It does not perform risk analysis, CBOM creation, or
    cross-tool correlation.
    """

    name = "semgrep"
    default_executable = "semgrep"

    def __init__(
        self,
        timeout_seconds: float = 300.0,
        rules_path: Path | None = None,
        executable: str | Path | None = None,
    ) -> None:
        """Configure a positive subprocess timeout, optional rule-file path, and optional executable path."""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = timeout_seconds
        self.rules_path = rules_path or Path(__file__).with_name("rules") / "ecdat-crypto.yml"
        self._custom_executable = str(executable) if executable is not None else None
        self.parser = SemgrepParser()

    @property
    def executable(self) -> str:
        """Return the executable command or path.

        Priority order:
        1. Explicit constructor argument (`executable=...`)
        2. Environment variables (`SEMGREP_PATH`, `ECDAT_SEMGREP_PATH`, or `SEMGREP_BINARY`)
        3. Default command name (`"semgrep"`) searched on system `PATH`.
        """
        if self._custom_executable:
            return self._custom_executable
        env_executable = (
            os.environ.get("SEMGREP_PATH")
            or os.environ.get("ECDAT_SEMGREP_PATH")
            or os.environ.get("SEMGREP_BINARY")
        )
        if env_executable:
            return env_executable
        return self.default_executable

    def build_command(self, target: Path) -> list[str]:
        """Build argv for Semgrep JSON output without invoking a shell."""
        return [
            self.executable,
            "scan",
            "--config",
            str(self.rules_path),
            "--json",
            "--quiet",
            "--no-git-ignore",
            str(target),
        ]


    def scan(self, target: Path) -> ScannerResult:
        """Execute Semgrep safely and normalize ECDAT crypto-rule results.

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
                message="Semgrep is not available on PATH.",
            )
        if not self.rules_path.is_file():
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Semgrep rule file does not exist: {self.rules_path}",
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
                message=f"Semgrep timed out after {self.timeout_seconds} seconds.",
                raw_output=_as_text(error.stdout),
                stderr=_as_text(error.stderr),
                command=tuple(command),
            )
        except OSError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Semgrep could not be started: {error}",
                command=tuple(command),
            )

        try:
            findings = self.parser.parse(completed.stdout, target)
        except SemgrepParseError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Semgrep returned unparseable JSON: {error}",
                raw_output=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                command=tuple(command),
            )

        message = "Semgrep scan completed."
        if completed.returncode != 0:
            message = f"Semgrep scan completed with exit code {completed.returncode}."
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
