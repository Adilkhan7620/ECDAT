"""Compliance Knowledge Base and Policy Framework definitions for ECDAT."""

from __future__ import annotations

from scanner.models.classified_asset import CryptoClassification
from scanner.models.compliance import (
    ComplianceFramework,
    PolicyApplicability,
    PolicyControl,
)


class PolicyKnowledgeBase:
    """Maintainable Policy Knowledge Base containing DST-NQM, RBI-QSAFE, and CNSA 2.0 definitions."""

    # Framework definitions
    FRAMEWORKS: dict[str, ComplianceFramework] = {
        "DST-NQM": ComplianceFramework(
            framework_id="DST-NQM",
            name="National Quantum Mission (DST-NQM)",
            version="1.0",
            description="India Department of Science & Technology National Quantum Mission cryptographic inventory, risk assessment, and PQC transition guidance.",
            authority="Department of Science & Technology (DST), Govt. of India",
        ),
        "RBI-QSAFE": ComplianceFramework(
            framework_id="RBI-QSAFE",
            name="Reserve Bank of India Cyber Security & Quantum Preparedness (RBI-QSAFE)",
            version="1.0",
            description="RBI guidance on quantum-safe preparedness, financial sector cryptographic asset discovery, and high-confidentiality HNDL protection.",
            authority="Reserve Bank of India (RBI)",
        ),
        "CNSA-2.0": ComplianceFramework(
            framework_id="CNSA-2.0",
            name="Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)",
            version="2.0",
            description="NSA Cybersecurity Advisory on Post-Quantum Cryptography transition timelines for national security systems and critical infrastructure.",
            authority="National Security Agency (NSA)",
        ),
    }

    # Policy Control definitions
    CONTROLS: dict[str, list[PolicyControl]] = {
        "DST-NQM": [
            PolicyControl(
                control_id="DST-NQM-CTRL-1",
                framework_id="DST-NQM",
                title="Cryptographic Asset Discovery & Inventory",
                description="Maintain an explicit inventory of cryptographic algorithms, keys, certificates, and libraries used across systems.",
                category="Inventory",
            ),
            PolicyControl(
                control_id="DST-NQM-CTRL-2",
                framework_id="DST-NQM",
                title="Post-Quantum Cryptographic Readiness & Migration",
                description="Identify quantum-vulnerable public-key algorithms and establish migration plans to NIST-standardized PQC algorithms (ML-KEM / ML-DSA).",
                category="PQC Migration",
                applicable_algorithms=("RSA", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448"),
            ),
        ],
        "RBI-QSAFE": [
            PolicyControl(
                control_id="RBI-QSAFE-CTRL-1",
                framework_id="RBI-QSAFE",
                title="Harvest-Now-Decrypt-Later (HNDL) Data Protection",
                description="Protect high-confidentiality financial data against HNDL risks where data lifetime extends into the CRQC horizon.",
                category="Data Security",
            ),
            PolicyControl(
                control_id="RBI-QSAFE-CTRL-2",
                framework_id="RBI-QSAFE",
                title="Critical Financial Infrastructure Quantum Readiness",
                description="High-criticality financial applications using quantum-vulnerable cryptography must prioritize hybrid/PQC transition.",
                category="Infrastructure Security",
            ),
        ],
        "CNSA-2.0": [
            PolicyControl(
                control_id="CNSA-2.0-CTRL-1",
                framework_id="CNSA-2.0",
                title="Public-Key Cryptography Modernization",
                description="Transition from classical asymmetric algorithms (RSA, ECDSA, ECDH, DH) to CNSA 2.0 approved post-quantum algorithms.",
                category="Algorithm Standards",
                applicable_algorithms=("RSA", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448"),
            ),
            PolicyControl(
                control_id="CNSA-2.0-CTRL-2",
                framework_id="CNSA-2.0",
                title="Classical Hash & Symmetric Cryptographic Strength",
                description="Deprecate legacy broken hashes (MD5, SHA-1) and ensure symmetric encryption maintains adequate security margins (AES-256).",
                category="Symmetric & Hash Standards",
                applicable_algorithms=("MD5", "SHA-1", "AES"),
            ),
        ],
    }

    @classmethod
    def get_framework(cls, framework_id: str) -> ComplianceFramework | None:
        """Return a ComplianceFramework definition by ID."""
        return cls.FRAMEWORKS.get(framework_id)

    @classmethod
    def get_controls(cls, framework_id: str) -> tuple[PolicyControl, ...]:
        """Return tuple of PolicyControl objects for a framework ID."""
        return tuple(cls.CONTROLS.get(framework_id, []))
