"""Quantum Cryptographic Risk Engine implementation for ECDAT."""

from __future__ import annotations

from typing import Sequence

from shared.models.finding import CryptoUsage
from scanner.models.classified_asset import (
    ClassifiedCryptoAsset,
    CryptoClassification,
    EvidenceConfidence,
)
from scanner.models.quantum_risk import (
    AlgorithmKnowledgeBase,
    AlgorithmQuantumProfile,
    QuantumRiskAssessment,
    QuantumVulnerabilityClass,
    RiskLevel,
)


class QuantumRiskEngine:
    """Deterministic, rule-based Quantum Risk Engine for ECDAT discovery assets.

    Evaluates Shor/Grover vulnerability, Mosca timing condition, HNDL exposure, and key sizes.
    """

    DEFAULT_YEARS_UNTIL_CRQC: float = 10.0

    def assess(
        self,
        asset: ClassifiedCryptoAsset,
        data_lifetime_years: float | None = None,
        migration_time_years: float | None = None,
        years_until_crqc: float | None = None,
    ) -> QuantumRiskAssessment:
        """Perform a quantum risk assessment for a single ClassifiedCryptoAsset."""
        crqc_horizon = (
            years_until_crqc if years_until_crqc is not None else self.DEFAULT_YEARS_UNTIL_CRQC
        )

        algorithm_name = asset.algorithm
        profile = AlgorithmKnowledgeBase.get_profile(algorithm_name)
        key_size = asset.key_size
        usage = asset.usage

        factors: list[str] = []

        # 1. Missing algorithm or unknown classification handling
        if not algorithm_name or asset.classification == CryptoClassification.UNKNOWN_CRYPTO:
            factors.append("Algorithm missing or unclassified asset")
            rationale = "Insufficient evidence or missing algorithm; quantum risk cannot be reliably evaluated."
            return QuantumRiskAssessment(
                asset_id=asset.asset_id,
                risk_level=RiskLevel.UNKNOWN,
                risk_score=0.0,
                algorithm=algorithm_name,
                key_size=key_size,
                usage=usage,
                data_lifetime_years=data_lifetime_years,
                migration_time_years=migration_time_years,
                years_until_crqc=crqc_horizon,
                hndl_exposure="UNKNOWN",
                rationale=rationale,
                contributing_factors=tuple(factors),
                confidence=asset.confidence,
            )

        # 2. HNDL Exposure evaluation
        # Confidentiality assets (encryption, key exchange, private keys, certs protecting TLS)
        is_confidentiality = (
            usage in (CryptoUsage.ENCRYPTION, CryptoUsage.KEY_EXCHANGE)
            or asset.classification in (
                CryptoClassification.ENCRYPTION_ALGORITHM,
                CryptoClassification.KEY_EXCHANGE_ALGORITHM,
                CryptoClassification.PRIVATE_KEY,
                CryptoClassification.CERTIFICATE,
            )
            or (profile is not None and profile.impacts_confidentiality and usage != CryptoUsage.DIGITAL_SIGNATURE)
        )

        hndl_exposure = "NONE"
        if profile and profile.vulnerability_class == QuantumVulnerabilityClass.SHOR_VULNERABLE and is_confidentiality:
            if data_lifetime_years is not None and data_lifetime_years > 0:
                hndl_exposure = "HIGH"
                factors.append(f"HNDL exposure HIGH: {algorithm_name} protects confidentiality with a {data_lifetime_years}-year data lifetime")
            elif data_lifetime_years is None:
                hndl_exposure = "POSSIBLE"
                factors.append(f"HNDL exposure POSSIBLE: {algorithm_name} protects confidentiality, but data lifetime is unstated")

        # 3. Mosca Timing Condition
        # (data_lifetime_years + migration_time_years) > years_until_crqc
        mosca_triggered = False
        if data_lifetime_years is not None and migration_time_years is not None:
            total_time = data_lifetime_years + migration_time_years
            if total_time > crqc_horizon:
                mosca_triggered = True
                factors.append(
                    f"Mosca timing condition triggered: ({data_lifetime_years}yr data lifetime + {migration_time_years}yr migration) > {crqc_horizon}yr CRQC horizon"
                )

        # 4. Risk Level & Score Determination
        base_score = 0.0
        risk_level = RiskLevel.INFORMATIONAL

        if profile:
            if profile.vulnerability_class == QuantumVulnerabilityClass.SHOR_VULNERABLE:
                factors.append(f"{algorithm_name} is vulnerable to Shor-style quantum attacks ({profile.primary_attack})")
                base_score = 80.0

                # Key size adjustments
                if key_size is not None:
                    factors.append(f"Key size: {key_size} bits")
                    if key_size < 2048 and algorithm_name == "RSA":
                        base_score = 90.0
                        factors.append("RSA key size below 2048 bits increases vulnerability")

                # Mosca condition elevation
                if mosca_triggered and is_confidentiality:
                    base_score = 95.0
                    risk_level = RiskLevel.CRITICAL
                elif is_confidentiality or usage == CryptoUsage.KEY_EXCHANGE:
                    risk_level = RiskLevel.HIGH
                else:
                    # Signatures / Integrity (e.g. ECDSA, Ed25519)
                    risk_level = RiskLevel.HIGH
                    base_score = 75.0

            elif profile.vulnerability_class == QuantumVulnerabilityClass.GROVER_AFFECTED:
                factors.append(f"{algorithm_name} is affected by Grover-style search speedup ({profile.primary_attack})")
                if algorithm_name in ("SHA-1", "MD5"):
                    base_score = 65.0
                    risk_level = RiskLevel.MEDIUM
                    factors.append(f"{algorithm_name} is additionally classically broken for collision resistance")
                elif key_size is not None and key_size < 256 and algorithm_name == "AES":
                    base_score = 40.0
                    risk_level = RiskLevel.MEDIUM
                    factors.append("AES-128 effective quantum security is reduced to 64 bits")
                elif algorithm_name == "AES" and key_size == 256:
                    base_score = 15.0
                    risk_level = RiskLevel.LOW
                    factors.append("AES-256 retains 128-bit quantum security post-Grover")
                else:
                    base_score = 30.0
                    risk_level = RiskLevel.LOW

            elif profile.vulnerability_class == QuantumVulnerabilityClass.QUANTUM_RESISTANT:
                base_score = 5.0
                risk_level = RiskLevel.INFORMATIONAL
                factors.append(f"{algorithm_name} is considered quantum-resistant")
        else:
            factors.append(f"Algorithm {algorithm_name} unknown to quantum knowledge base")
            risk_level = RiskLevel.UNKNOWN
            base_score = 0.0

        # Adjust score if data lifetime missing for Shor confidential algorithms
        assessment_confidence = asset.confidence
        if is_confidentiality and data_lifetime_years is None and profile and profile.vulnerability_class == QuantumVulnerabilityClass.SHOR_VULNERABLE:
            factors.append("Data lifetime unavailable; HNDL timing assessment cannot be fully completed")
            if assessment_confidence == EvidenceConfidence.HIGH:
                assessment_confidence = EvidenceConfidence.MEDIUM

        # 5. Build Human-Readable Rationale
        rationale_parts = []
        if profile:
            rationale_parts.append(f"{algorithm_name} is classified as {profile.vulnerability_class.value} under {profile.primary_attack}.")
        if usage:
            rationale_parts.append(f"Usage context: {usage.value}.")
        if is_confidentiality and data_lifetime_years is not None and migration_time_years is not None:
            rationale_parts.append(
                f"Data lifetime is {data_lifetime_years} year(s) and migration time is {migration_time_years} year(s). "
                f"With a configured CRQC horizon of {crqc_horizon} year(s), "
                f"{'the Mosca timing condition IS triggered (' + str(data_lifetime_years) + ' + ' + str(migration_time_years) + ' > ' + str(crqc_horizon) + ').' if mosca_triggered else 'the Mosca timing condition is NOT triggered (' + str(data_lifetime_years) + ' + ' + str(migration_time_years) + ' <= ' + str(crqc_horizon) + ').'}"
            )
        elif is_confidentiality and data_lifetime_years is None:
            rationale_parts.append("Data lifetime is unavailable; HNDL timing assessment cannot be completed.")

        rationale_parts.append(f"Overall assessed quantum risk level is {risk_level.value} (score: {base_score:.1f}/100).")
        rationale = " ".join(rationale_parts)

        return QuantumRiskAssessment(
            asset_id=asset.asset_id,
            risk_level=risk_level,
            risk_score=base_score,
            algorithm=algorithm_name,
            key_size=key_size,
            usage=usage,
            data_lifetime_years=data_lifetime_years,
            migration_time_years=migration_time_years,
            years_until_crqc=crqc_horizon,
            hndl_exposure=hndl_exposure,
            rationale=rationale,
            contributing_factors=tuple(factors),
            confidence=assessment_confidence,
        )

    def assess_batch(
        self,
        assets: Sequence[ClassifiedCryptoAsset],
        data_lifetime_years: float | None = None,
        migration_time_years: float | None = None,
        years_until_crqc: float | None = None,
    ) -> tuple[QuantumRiskAssessment, ...]:
        """Assess a batch of ClassifiedCryptoAsset objects deterministically in input order."""
        assessments: list[QuantumRiskAssessment] = []
        for asset in assets:
            assessments.append(
                self.assess(
                    asset,
                    data_lifetime_years=data_lifetime_years,
                    migration_time_years=migration_time_years,
                    years_until_crqc=years_until_crqc,
                )
            )
        return tuple(assessments)
