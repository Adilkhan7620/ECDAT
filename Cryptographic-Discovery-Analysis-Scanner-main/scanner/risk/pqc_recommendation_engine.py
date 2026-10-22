"""PQC Migration Recommendation Engine implementation for ECDAT."""

from __future__ import annotations

from typing import Sequence

from shared.models.finding import CryptoUsage
from scanner.models.blast_radius import BlastRadiusAssessment, BlastRadiusLevel
from scanner.models.classified_asset import (
    ClassifiedCryptoAsset,
    CryptoClassification,
)
from scanner.models.pqc_recommendation import (
    MigrationEffort,
    MigrationPriority,
    MigrationStrategy,
    PqcKnowledgeBase,
    PqcMigrationRecommendation,
)
from scanner.models.quantum_risk import QuantumRiskAssessment, RiskLevel


class PqcRecommendationEngine:
    """Deterministic, rule-based PQC Migration Recommendation Engine for ECDAT discovery assets."""

    def recommend(
        self,
        asset: ClassifiedCryptoAsset,
        quantum_risk: QuantumRiskAssessment | None = None,
        blast_radius: BlastRadiusAssessment | None = None,
    ) -> PqcMigrationRecommendation:
        """Generate a PQC migration recommendation for a single ClassifiedCryptoAsset."""
        asset_id = asset.asset_id
        alg = asset.algorithm
        usage = asset.usage
        key_size = asset.key_size

        q_risk_level = quantum_risk.risk_level if quantum_risk else RiskLevel.UNKNOWN
        b_radius_level = blast_radius.blast_radius_level if blast_radius else BlastRadiusLevel.UNKNOWN

        # 1. PQC Mapping Rules
        recommended_alg: str | None = None
        recommended_fam: str | None = None
        strategy = MigrationStrategy.MANUAL_REVIEW
        rationale_parts: list[str] = []
        compat_parts: list[str] = []
        hndl_parts: list[str] = []

        if not alg or asset.classification == CryptoClassification.UNKNOWN_CRYPTO:
            strategy = MigrationStrategy.MANUAL_REVIEW
            rationale_parts.append("Algorithm is unknown or unclassified; manual engineering review required before PQC mapping.")

        elif alg in ("RSA", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448"):
            if alg == "RSA":
                if usage in (CryptoUsage.ENCRYPTION, CryptoUsage.KEY_EXCHANGE):
                    recommended_alg = "ML-KEM"
                    recommended_fam = "FIPS 203 (Module-Lattice KEM)"
                    strategy = MigrationStrategy.HYBRID
                    rationale_parts.append(f"RSA used for {usage.value} is vulnerable to Shor's algorithm; recommend transition to ML-KEM.")
                elif usage == CryptoUsage.DIGITAL_SIGNATURE:
                    recommended_alg = "ML-DSA"
                    recommended_fam = "FIPS 204 (Module-Lattice DSA)"
                    strategy = MigrationStrategy.HYBRID
                    rationale_parts.append("RSA used for digital signature is vulnerable to Shor's algorithm; recommend transition to ML-DSA.")
                else:
                    strategy = MigrationStrategy.MANUAL_REVIEW
                    rationale_parts.append("RSA cryptographic usage is ambiguous or unspecified; conditional manual review required to select ML-KEM or ML-DSA.")

            elif alg in ("ECDH", "DH"):
                recommended_alg = "ML-KEM"
                recommended_fam = "FIPS 203 (Module-Lattice KEM)"
                strategy = MigrationStrategy.HYBRID
                rationale_parts.append(f"{alg} key establishment is vulnerable to Shor's algorithm; recommend transition to ML-KEM key encapsulation.")

            elif alg in ("ECDSA", "Ed25519", "Ed448"):
                recommended_alg = "ML-DSA"
                recommended_fam = "FIPS 204 (Module-Lattice DSA)"
                strategy = MigrationStrategy.HYBRID if alg == "ECDSA" else MigrationStrategy.DIRECT_PQC
                rationale_parts.append(f"{alg} signature algorithm is vulnerable to Shor's algorithm; recommend transition to ML-DSA.")

            # Certificate / TLS considerations
            if asset.classification in (CryptoClassification.CERTIFICATE, CryptoClassification.TLS_CONFIGURATION):
                compat_parts.append("Migration requires certificate authority PKI re-issuance, key-pair replacement, and TLS protocol client/server compatibility validation.")

        elif alg == "AES":
            if key_size == 128:
                recommended_alg = "AES-256"
                recommended_fam = "Symmetric Block Cipher (Post-Quantum Security)"
                strategy = MigrationStrategy.RETAIN_MONITOR
                rationale_parts.append("AES-128 effective security is reduced to 64 bits under Grover's algorithm; evaluate upgrade to AES-256 for 128-bit quantum security margin.")
            elif key_size == 256:
                recommended_alg = "AES-256"
                recommended_fam = "Symmetric Block Cipher (Post-Quantum Security)"
                strategy = MigrationStrategy.RETAIN_MONITOR
                rationale_parts.append("AES-256 retains 128-bit quantum security post-Grover; retain and monitor without urgent PQC replacement.")
            else:
                recommended_alg = "AES-256"
                recommended_fam = "Symmetric Block Cipher"
                strategy = MigrationStrategy.RETAIN_MONITOR
                rationale_parts.append("AES symmetric cipher; retain and monitor.")

        elif alg in ("ChaCha20", "SHA-256", "SHA-384", "SHA-512"):
            recommended_alg = alg
            recommended_fam = "Symmetric / Hash"
            strategy = MigrationStrategy.RETAIN_MONITOR
            rationale_parts.append(f"{alg} retains strong quantum security margin under Grover's algorithm; retain and monitor without PQC replacement.")

        elif alg in ("SHA-1", "MD5"):
            recommended_alg = "SHA-256 / SHA-512"
            recommended_fam = "Cryptographic Hash Standard"
            strategy = MigrationStrategy.DEPRECATE
            rationale_parts.append(f"{alg} is classically broken for collision resistance; recommend classical cryptographic deprecation and upgrade to SHA-256/SHA-512.")

        else:
            strategy = MigrationStrategy.MANUAL_REVIEW
            rationale_parts.append(f"Algorithm {alg} requires manual cryptographic review.")

        # 2. HNDL Consideration Integration
        if quantum_risk:
            if quantum_risk.hndl_exposure == "HIGH":
                hndl_parts.append("HIGH Harvest-Now-Decrypt-Later (HNDL) exposure detected; confidential data lifetime requires urgent migration prioritization.")
            elif quantum_risk.hndl_exposure == "POSSIBLE":
                hndl_parts.append("POSSIBLE Harvest-Now-Decrypt-Later (HNDL) exposure; data lifetime should be confirmed.")

        # 3. Migration Priority Matrix
        # Combine QuantumRisk + BusinessBlastRadius + HNDL
        priority = self._calculate_priority(q_risk_level, b_radius_level, quantum_risk)

        # 4. Migration Effort Heuristic
        effort = self._calculate_effort(asset, blast_radius, strategy)

        # Build output
        rationale = " ".join(rationale_parts)
        compatibility = " ".join(compat_parts)
        hndl_text = " ".join(hndl_parts)
        supporting_ids = asset.supporting_finding_ids

        return PqcMigrationRecommendation(
            asset_id=asset_id,
            current_algorithm=alg,
            current_usage=usage,
            current_key_size=key_size,
            recommended_algorithm=recommended_alg,
            recommended_family=recommended_fam,
            migration_strategy=strategy,
            migration_priority=priority,
            migration_effort=effort,
            rationale=rationale,
            compatibility_considerations=compatibility,
            hndl_consideration=hndl_text,
            quantum_risk_level=q_risk_level,
            blast_radius_level=b_radius_level,
            supporting_finding_ids=supporting_ids,
            metadata=asset.metadata,
        )

    def _calculate_priority(
        self,
        q_risk: RiskLevel,
        b_radius: BlastRadiusLevel,
        quantum_risk: QuantumRiskAssessment | None,
    ) -> MigrationPriority:
        """Calculate migration priority using deterministic matrix."""
        # P0 Rule: Critical Quantum Risk + Critical Blast Radius, OR High HNDL + Critical Blast Radius
        if (q_risk == RiskLevel.CRITICAL and b_radius == BlastRadiusLevel.CRITICAL) or (
            quantum_risk and quantum_risk.hndl_exposure == "HIGH" and b_radius == BlastRadiusLevel.CRITICAL
        ):
            return MigrationPriority.P0

        # P1 Rule: High/Critical Quantum Risk + Large/Critical Blast Radius, OR High HNDL + Large Blast Radius
        if (q_risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) and b_radius in (BlastRadiusLevel.CRITICAL, BlastRadiusLevel.LARGE)) or (
            quantum_risk and quantum_risk.hndl_exposure == "HIGH" and b_radius == BlastRadiusLevel.LARGE
        ):
            return MigrationPriority.P1

        # P2 Rule: High Quantum Risk + Medium/Small/Unknown Blast Radius, OR Medium Quantum Risk + Large/Critical Blast Radius
        if (q_risk == RiskLevel.HIGH) or (q_risk == RiskLevel.MEDIUM and b_radius in (BlastRadiusLevel.CRITICAL, BlastRadiusLevel.LARGE)):
            return MigrationPriority.P2

        # MONITOR Rule: Informational / Low Quantum Risk / Quantum Resistant algorithms
        if q_risk in (RiskLevel.LOW, RiskLevel.INFORMATIONAL, RiskLevel.UNKNOWN) and b_radius in (BlastRadiusLevel.SMALL, BlastRadiusLevel.UNKNOWN):
            return MigrationPriority.MONITOR

        # P3 Rule: Medium/Low Quantum Risk + Medium Blast Radius, OR Deprecated classical algorithms
        if q_risk in (RiskLevel.MEDIUM, RiskLevel.LOW):
            return MigrationPriority.P3

        return MigrationPriority.P3

    def _calculate_effort(
        self,
        asset: ClassifiedCryptoAsset,
        blast_radius: BlastRadiusAssessment | None,
        strategy: MigrationStrategy,
    ) -> MigrationEffort:
        """Calculate estimated engineering migration effort category."""
        if strategy == MigrationStrategy.MANUAL_REVIEW:
            return MigrationEffort.UNKNOWN

        if strategy == MigrationStrategy.RETAIN_MONITOR:
            return MigrationEffort.LOW

        app_count = len(blast_radius.affected_applications) if blast_radius else 1

        if (
            asset.classification in (CryptoClassification.CERTIFICATE, CryptoClassification.TLS_CONFIGURATION)
            or app_count >= 3
            or strategy == MigrationStrategy.HYBRID
        ):
            return MigrationEffort.HIGH

        if app_count >= 2 or strategy in (MigrationStrategy.DIRECT_PQC, MigrationStrategy.DEPRECATE):
            return MigrationEffort.MEDIUM

        return MigrationEffort.LOW

    def recommend_batch(
        self,
        assets: Sequence[ClassifiedCryptoAsset],
        quantum_risks: Sequence[QuantumRiskAssessment] | None = None,
        blast_radii: Sequence[BlastRadiusAssessment] | None = None,
    ) -> tuple[PqcMigrationRecommendation, ...]:
        """Generate recommendations for a batch of ClassifiedCryptoAsset objects in input order."""
        q_map: dict[str, QuantumRiskAssessment] = {r.asset_id: r for r in quantum_risks} if quantum_risks else {}
        b_map: dict[str, BlastRadiusAssessment] = {b.asset_id: b for b in blast_radii} if blast_radii else {}

        recommendations: list[PqcMigrationRecommendation] = []
        for asset in assets:
            q_risk = q_map.get(asset.asset_id)
            b_radius = b_map.get(asset.asset_id)
            recommendations.append(
                self.recommend(
                    asset=asset,
                    quantum_risk=q_risk,
                    blast_radius=b_radius,
                )
            )
        return tuple(recommendations)
