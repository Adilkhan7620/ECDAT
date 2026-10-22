"""Scanner-specific adapters for the documented ECDAT tools."""

from scanner.scanners.gitleaks.scanner import GitleaksScanner
from scanner.scanners.openssl.scanner import OpenSSLScanner
from scanner.scanners.semgrep.scanner import SemgrepScanner
from scanner.scanners.syft.scanner import SyftScanner
from scanner.scanners.trivy.scanner import TrivyScanner

__all__ = [
    "GitleaksScanner",
    "OpenSSLScanner",
    "SemgrepScanner",
    "SyftScanner",
    "TrivyScanner",
]
