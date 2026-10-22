"""Parser that converts OpenSSL certificate and TLS output into ECDAT Findings."""

from __future__ import annotations

import re
from pathlib import Path, PurePath
from uuid import NAMESPACE_URL, uuid5

from shared.models import (
    Finding,
    FindingCategory,
    FindingSource,
    ToolEvidence,
    ToolName,
)


class OpenSSLParseError(ValueError):
    """Raised when OpenSSL output cannot be interpreted."""


class OpenSSLParser:
    """Normalize OpenSSL x509 and s_client text outputs into ECDAT Findings."""

    def parse_x509(self, text: str, file_path: str | None = None) -> Finding | None:
        """Parse `openssl x509 -text` output into an ECDAT certificate Finding."""
        if not text or "Certificate:" not in text:
            return None

        subject = self._extract_regex(r"Subject:\s*(.*)", text)
        issuer = self._extract_regex(r"Issuer:\s*(.*)", text)
        serial = self._extract_regex(r"Serial Number:\s*(.*)", text)
        not_before = self._extract_regex(r"Not Before:\s*(.*)", text)
        not_after = self._extract_regex(r"Not After\s*:\s*(.*)", text)
        sig_alg = self._extract_regex(r"Signature Algorithm:\s*([A-Za-z0-9_\-]+)", text)
        pubkey_alg = self._extract_regex(r"Public Key Algorithm:\s*([A-Za-z0-9_\-]+)", text)
        bits_str = self._extract_regex(r"Public-Key:\s*\((\d+)\s*bit\)", text)

        key_size = int(bits_str) if bits_str and bits_str.isdigit() else None
        canonical_alg = self._normalize_algorithm(pubkey_alg)

        metadata: dict[str, object] = {}
        if subject:
            metadata["subject"] = subject
        if issuer:
            metadata["issuer"] = issuer
        if serial:
            metadata["serial_number"] = serial
        if not_before:
            metadata["validity_not_before"] = not_before
        if not_after:
            metadata["validity_not_after"] = not_after
        if sig_alg:
            metadata["signature_algorithm"] = sig_alg
        if pubkey_alg:
            metadata["public_key_algorithm"] = pubkey_alg

        san_match = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.*)", text)
        if san_match:
            metadata["sans"] = san_match.group(1).strip()

        message = f"OpenSSL X.509 certificate observation: {subject or 'unknown'}"
        finding_key = f"openssl:x509:{file_path}:{subject}:{serial}"

        return Finding(
            finding_id=str(uuid5(NAMESPACE_URL, finding_key)),
            tool=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            evidence=ToolEvidence(
                message=message,
                original=metadata,
                raw_artifact="raw/openssl.json",
                raw_pointer=f"/{file_path or 'x509'}",
            ),
            metadata=metadata,
            algorithm=canonical_alg,
            key_size=key_size,
            file=file_path,
            line=None,
            severity=None,
            rule="x509-certificate",
        )

    def parse_sclient(self, text: str, endpoint: str) -> tuple[Finding, ...]:
        """Parse `openssl s_client` output into ECDAT TLS Findings."""
        if not text:
            return ()

        findings: list[Finding] = []

        protocol = self._extract_regex(r"Protocol\s*:\s*([A-Za-z0-9_\.\-]+)", text)
        cipher = self._extract_regex(r"Cipher\s*:\s*([A-Za-z0-9_\.\-]+)", text)
        subject = self._extract_regex(r"subject=(.*)", text)
        issuer = self._extract_regex(r"issuer=(.*)", text)
        temp_key = self._extract_regex(r"Server Temp Key:\s*(.*)", text)
        sig_type = self._extract_regex(r"Peer signature type:\s*(.*)", text)

        metadata: dict[str, object] = {"endpoint": endpoint}
        if protocol:
            metadata["protocol"] = protocol
        if cipher:
            metadata["cipher"] = cipher
        if subject:
            metadata["subject"] = subject
        if issuer:
            metadata["issuer"] = issuer
        if temp_key:
            metadata["server_temp_key"] = temp_key
        if sig_type:
            metadata["peer_signature_type"] = sig_type

        # Extract algorithm from cipher suite or temp key if present
        canonical_alg = self._infer_tls_algorithm(cipher, temp_key, sig_type)
        key_size = self._infer_key_size(temp_key)

        message = f"OpenSSL TLS endpoint observation: {endpoint} ({protocol or 'TLS'})"
        finding_key = f"openssl:sclient:{endpoint}:{protocol}:{cipher}"

        finding = Finding(
            finding_id=str(uuid5(NAMESPACE_URL, finding_key)),
            tool=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CONFIGURATION,
            evidence=ToolEvidence(
                message=message,
                original=metadata,
                raw_artifact="raw/openssl.json",
                raw_pointer=f"/endpoint/{endpoint}",
            ),
            metadata=metadata,
            algorithm=canonical_alg,
            key_size=key_size,
            file=None,
            line=None,
            severity=None,
            rule="tls-endpoint",
        )
        findings.append(finding)
        return tuple(findings)

    @staticmethod
    def _extract_regex(pattern: str, text: str) -> str | None:
        """Extract first regex match string or return None."""
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else None

    @staticmethod
    def _normalize_algorithm(pubkey_alg: str | None) -> str | None:
        """Map OpenSSL public key algorithm string to canonical name."""
        if not pubkey_alg:
            return None
        alg_lower = pubkey_alg.lower()
        if "rsa" in alg_lower:
            return "RSA"
        if "ec" in alg_lower or "ecdsa" in alg_lower:
            return "ECDSA"
        if "ed25519" in alg_lower:
            return "Ed25519"
        if "ed448" in alg_lower:
            return "Ed448"
        return pubkey_alg

    @staticmethod
    def _infer_tls_algorithm(cipher: str | None, temp_key: str | None, sig_type: str | None) -> str | None:
        """Extract canonical algorithm from TLS cipher or key negotiation strings."""
        combined = f"{cipher or ''} {temp_key or ''} {sig_type or ''}".lower()
        if "ecdhe" in combined or "ecdh" in combined or "ecdsa" in combined:
            return "ECDSA"
        if "rsa" in combined:
            return "RSA"
        if "aes" in combined:
            return "AES"
        return None

    @staticmethod
    def _infer_key_size(temp_key: str | None) -> int | None:
        """Extract key size in bits from server temp key string if present."""
        if not temp_key:
            return None
        match = re.search(r"(\d+)\s*bits?", temp_key, re.IGNORECASE)
        return int(match.group(1)) if match else None
