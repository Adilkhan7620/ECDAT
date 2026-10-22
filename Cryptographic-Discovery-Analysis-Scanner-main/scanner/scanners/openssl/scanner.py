"""Safe OpenSSL execution adapter for certificate and TLS endpoint analysis."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from scanner.core.base_scanner import BaseScanner
from scanner.models.finding import Finding
from scanner.models.scan_result import ScannerResult, ScannerStatus
from scanner.scanners.openssl.parser import OpenSSLParseError, OpenSSLParser


class OpenSSLScanner(BaseScanner):
    """Run OpenSSL X.509 certificate and TLS endpoint discovery.

    Supports local certificate file inspection and explicit host:port TLS
    endpoint scanning. Private keys are never inspected, requested, or output.
    """

    name = "openssl"
    default_executable = "openssl"
    _CERT_EXTENSIONS = {".crt", ".pem", ".cer", ".der", ".pub"}

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
        self.parser = OpenSSLParser()

    @property
    def executable(self) -> str:
        """Return the executable command or path.

        Priority order:
        1. Explicit constructor argument (`executable=...`)
        2. Environment variables (`OPENSSL_PATH`, `ECDAT_OPENSSL_PATH`, or `OPENSSL_BINARY`)
        3. Default command name (`"openssl"`) searched on system `PATH`.
        """
        if self._custom_executable:
            return self._custom_executable
        env_executable = (
            os.environ.get("OPENSSL_PATH")
            or os.environ.get("ECDAT_OPENSSL_PATH")
            or os.environ.get("OPENSSL_BINARY")
        )
        if env_executable:
            return env_executable
        return self.default_executable

    def scan(self, target: Path) -> ScannerResult:
        """Execute OpenSSL safely for certificate files or host:port endpoints."""
        target_str = str(target).strip()
        if not self.is_available():
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.TOOL_UNAVAILABLE,
                message="OpenSSL is not available on PATH.",
            )

        # Check if target is a TLS endpoint (host:port)
        if ":" in target_str and not target.exists():
            return self._scan_endpoint(target_str)

        # Local directory/file target
        if not target.exists():
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Target must be an existing local file/directory or valid endpoint: {target}",
            )

        return self._scan_local_target(target)

    def _scan_endpoint(self, endpoint: str) -> ScannerResult:
        """Inspect a host:port TLS endpoint safely via s_client."""
        parsed = self.validate_endpoint(endpoint)
        if parsed is None:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"Invalid TLS endpoint format: {endpoint!r}. Expected 'hostname:port'.",
            )
        host, port = parsed

        command = [
            self.executable,
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-servername",
            host,
            "-showcerts",
        ]

        try:
            completed = subprocess.run(
                command,
                check=False,
                shell=False,
                input="",
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"OpenSSL s_client timed out connecting to {endpoint}.",
                raw_output=_as_text(error.stdout),
                stderr=_as_text(error.stderr),
                command=tuple(command),
            )
        except OSError as error:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message=f"OpenSSL could not be started: {error}",
                command=tuple(command),
            )

        findings = self.parser.parse_sclient(completed.stdout, endpoint)
        return ScannerResult(
            scanner=self.name,
            status=ScannerStatus.COMPLETED,
            message=f"OpenSSL TLS endpoint scan completed for {endpoint}.",
            findings=findings,
            raw_output=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            command=tuple(command),
        )

    def _scan_local_target(self, target: Path) -> ScannerResult:
        """Scan eligible certificate files under a local target path."""
        files_to_scan: list[Path] = []
        if target.is_file():
            files_to_scan.append(target)
        else:
            for file_path in target.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in self._CERT_EXTENSIONS:
                    files_to_scan.append(file_path)

        all_findings: list[Finding] = []
        raw_outputs: list[str] = []
        stderrs: list[str] = []

        for file_path in files_to_scan:
            rel_path = self._relative_file(file_path, target)
            cmd = [self.executable, "x509", "-in", str(file_path), "-text", "-noout"]
            try:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
                if completed.returncode == 0 and completed.stdout:
                    finding = self.parser.parse_x509(completed.stdout, rel_path)
                    if finding:
                        all_findings.append(finding)
                        raw_outputs.append(completed.stdout)
            except (subprocess.TimeoutExpired, OSError):
                continue

        message = f"OpenSSL scan completed ({len(all_findings)} certificate finding(s))."
        return ScannerResult(
            scanner=self.name,
            status=ScannerStatus.COMPLETED,
            message=message,
            findings=tuple(all_findings),
            raw_output="\n---\n".join(raw_outputs) if raw_outputs else "",
            stderr="\n".join(stderrs),
            exit_code=0,
            command=(self.executable, "x509"),
        )

    @staticmethod
    def validate_endpoint(endpoint: str) -> tuple[str, int] | None:
        """Validate and parse host:port string safely, rejecting flags or malformed inputs."""
        if not endpoint or endpoint.startswith("-"):
            return None
        match = re.match(r"^([a-zA-Z0-9\.\_\-]+):(\d{1,5})$", endpoint.strip())
        if not match:
            return None
        host, port_str = match.groups()
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
        return host, port

    @staticmethod
    def _relative_file(file_path: Path, target: Path) -> str:
        """Return target-relative path string."""
        if target.is_file():
            return file_path.name
        try:
            return str(file_path.resolve().relative_to(target.resolve()))
        except ValueError:
            return file_path.name


def _as_text(value: str | bytes | None) -> str | None:
    """Normalize timeout-captured streams to text without losing content."""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
