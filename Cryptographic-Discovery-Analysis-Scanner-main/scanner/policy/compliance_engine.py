"""Compliance Policy Engine implementation for ECDAT."""

from __future__ import annotations

from typing import Sequence

from scanner.models.blast_radius import BlastRadiusAssessment, BlastRadiusLevel, BusinessCriticality
from scanner.models.classified_asset import ClassifiedCryptoAsset, CryptoClassification
from scanner.models.compliance import (
    ComplianceAssessment,
    ComplianceFramework,
    ComplianceStatus,
    FrameworkComplianceResult,
    PolicyApplicability,
    PolicyControl,
)
from scanner.models.pqc_recommendation import PqcMigrationRecommendation
from scanner.models.quantum_risk import QuantumRiskAssessment, RiskLevel
from scanner.policy.policy_knowledge_base import PolicyKnowledgeBase


class CompliancePolicyEngine:
    """Deterministic, rule-based Compliance and Policy Mapping Engine for ECDAT.

    Maps discovery evidence and assessments to DST-NQM, RBI-QSAFE, and CNSA 2.0 policy controls.
    """

    def assess_asset_against_control(
        self,
        asset: ClassifiedCryptoAsset,
        control: PolicyControl,
        framework_applicability: PolicyApplicability,
        quantum_risk: QuantumRiskAssessment | None = None,
        blast_radius: BlastRadiusAssessment | None = None,
        pqc_rec: PqcMigrationRecommendation | None = None,
    ) -> ComplianceAssessment:
        """Evaluate a single ClassifiedCryptoAsset against a PolicyControl."""
        asset_id = asset.asset_id
        framework_id = control.framework_id
        control_id = control.control_id
        alg = asset.algorithm

        q_level = quantum_risk.risk_level if quantum_risk else RiskLevel.UNKNOWN
        b_level = blast_radius.blast_radius_level if blast_radius else BlastRadiusLevel.UNKNOWN

        # 1. Applicability Check
        if framework_applicability == PolicyApplicability.NOT_APPLICABLE:
            return ComplianceAssessment(
                asset_id=asset_id,
                framework_id=framework_id,
                control_id=control_id,
                status=ComplianceStatus.NOT_APPLICABLE,
                rationale=f"Framework {framework_id} is explicitly set as NOT_APPLICABLE for this organization.",
                supporting_finding_ids=asset.supporting_finding_ids,
                quantum_risk_level=q_level,
                blast_radius_level=b_level,
                pqc_recommendation=pqc_rec,
            )

        if framework_applicability == PolicyApplicability.UNKNOWN:
            return ComplianceAssessment(
                asset_id=asset_id,
                framework_id=framework_id,
                control_id=control_id,
                status=ComplianceStatus.UNKNOWN,
                rationale=f"Applicability for framework {framework_id} is UNKNOWN; compliance mapping cannot be completed.",
                supporting_finding_ids=asset.supporting_finding_ids,
                quantum_risk_level=q_level,
                blast_radius_level=b_level,
                pqc_recommendation=pqc_rec,
            )

        # 2. Missing Algorithm / Evidence
        if not alg or asset.classification == CryptoClassification.UNKNOWN_CRYPTO:
            return ComplianceAssessment(
                asset_id=asset_id,
                framework_id=framework_id,
                control_id=control_id,
                status=ComplianceStatus.UNKNOWN,
                rationale="Missing algorithm or unclassified crypto finding; compliance control evaluation incomplete.",
                supporting_finding_ids=asset.supporting_finding_ids,
                quantum_risk_level=q_level,
                blast_radius_level=b_level,
                pqc_recommendation=pqc_rec,
            )

        # 3. Rule Evaluation per Control
        status = ComplianceStatus.ALIGNED
        rationale_parts: list[str] = []

        if framework_id == "DST-NQM":
            if control_id == "DST-NQM-CTRL-1":
                # Discovery & Inventory Control
                status = ComplianceStatus.ALIGNED
                rationale_parts.append("Cryptographic asset observed, normalized, and inventoried by ECDAT discovery engine.")
            elif control_id == "DST-NQM-CTRL-2":
                # PQC Readiness & Migration
                if alg in ("RSA", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448"):
                    status = ComplianceStatus.REQUIRES_ATTENTION
                    rationale_parts.append(f"Asset uses quantum-vulnerable public-key algorithm ({alg}). DST-NQM PQC readiness control requires attention.")
                    if pqc_rec:
                        rationale_parts.append(f"Recommended PQC target: {pqc_rec.recommended_algorithm or 'PQC transition'}.")
                else:
                    status = ComplianceStatus.ALIGNED
                    rationale_parts.append(f"Asset algorithm ({alg}) does not use quantum-vulnerable asymmetric cryptography.")

        elif framework_id == "RBI-QSAFE":
            if control_id == "RBI-QSAFE-CTRL-1":
                # HNDL Data Protection
                if quantum_risk and quantum_risk.hndl_exposure in ("HIGH", "POSSIBLE"):
                    status = ComplianceStatus.REQUIRES_ATTENTION
                    rationale_parts.append(f"RBI-QSAFE HNDL control requires attention: Asset has {quantum_risk.hndl_exposure} HNDL exposure protecting confidential data.")
                else:
                    status = ComplianceStatus.ALIGNED
                    rationale_parts.append("Asset has no identified HNDL confidentiality exposure.")
            elif control_id == "RBI-QSAFE-CTRL-2":
                # Financial Infrastructure Readiness
                if blast_radius and (blast_radius.criticality == BusinessCriticality.CRITICAL or blast_radius.blast_radius_level in (BlastRadiusLevel.CRITICAL, BlastRadiusLevel.LARGE)):
                    if alg in ("RSA", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448"):
                        status = ComplianceStatus.REQUIRES_ATTENTION
                        rationale_parts.append(f"RBI-QSAFE infrastructure control requires attention: Critical financial asset ({blast_radius.criticality.value}) uses quantum-vulnerable {alg}.")
                    else:
                        status = ComplianceStatus.ALIGNED
                        rationale_parts.append("Critical financial asset uses quantum-resistant or symmetric cryptography.")
                else:
                    status = ComplianceStatus.ALIGNED
                    rationale_parts.append("Non-critical asset satisfies basic infrastructure control requirement.")

        elif framework_id == "CNSA-2.0":
            if control_id == "CNSA-2.0-CTRL-1":
                # Public-Key Cryptography Modernization
                if alg in ("RSA", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448"):
                    status = ComplianceStatus.REQUIRES_ATTENTION
                    rationale_parts.append(f"CNSA 2.0 control REQUIRES_ATTENTION: Asymmetric algorithm {alg} must transition to CNSA 2.0 post-quantum standards.")
                else:
                    status = ComplianceStatus.ALIGNED
                    rationale_parts.append(f"Algorithm {alg} satisfies CNSA 2.0 asymmetric standard check.")
            elif control_id == "CNSA-2.0-CTRL-2":
                # Classical Hash & Symmetric
                if alg in ("MD5", "SHA-1"):
                    status = ComplianceStatus.GAP
                    rationale_parts.append(f"CNSA 2.0 GAP: Classically broken algorithm {alg} violates CNSA 2.0 hash security policy.")
                elif alg == "AES" and asset.key_size == 128:
                    status = ComplianceStatus.REQUIRES_ATTENTION
                    rationale_parts.append("CNSA 2.0 REQUIRES_ATTENTION: AES-128 should upgrade to AES-256 for CNSA 2.0 compliance.")
                else:
                    status = ComplianceStatus.ALIGNED
                    rationale_parts.append(f"Algorithm {alg} aligns with CNSA 2.0 symmetric/hash requirements.")

        else:
            status = ComplianceStatus.UNKNOWN
            rationale_parts.append(f"Unrecognized policy framework: {framework_id}.")

        rationale = " ".join(rationale_parts)
        evidence_summary = f"Algorithm: {alg}, Classification: {asset.classification.value}, Risk: {q_level.value}, Impact: {b_level.value}"

        return ComplianceAssessment(
            asset_id=asset_id,
            framework_id=framework_id,
            control_id=control_id,
            status=status,
            rationale=rationale,
            evidence_summary=evidence_summary,
            supporting_finding_ids=asset.supporting_finding_ids,
            quantum_risk_level=q_level,
            blast_radius_level=b_level,
            pqc_recommendation=pqc_rec,
        )

    def evaluate_framework(
        self,
        framework_id: str,
        assets: Sequence[ClassifiedCryptoAsset],
        applicability: PolicyApplicability = PolicyApplicability.APPLICABLE,
        quantum_risks: Sequence[QuantumRiskAssessment] | None = None,
        blast_radii: Sequence[BlastRadiusAssessment] | None = None,
        pqc_recs: Sequence[PqcMigrationRecommendation] | None = None,
    ) -> FrameworkComplianceResult:
        """Evaluate all assets against all controls of a framework deterministically."""
        framework = PolicyKnowledgeBase.get_framework(framework_id)
        if not framework:
            raise ValueError(f"Unknown framework_id: {framework_id}")

        controls = PolicyKnowledgeBase.get_controls(framework_id)
        q_map = {r.asset_id: r for r in quantum_risks} if quantum_risks else {}
        b_map = {b.asset_id: b for b in blast_radii} if blast_radii else {}
        p_map = {p.asset_id: p for p in pqc_recs} if pqc_recs else {}

        # Sorted asset evaluation for determinism
        sorted_assets = tuple(sorted(assets, key=lambda a: a.asset_id))
        sorted_controls = tuple(sorted(controls, key=lambda c: c.control_id))

        assessments: list[ComplianceAssessment] = []
        for asset in sorted_assets:
            q_risk = q_map.get(asset.asset_id)
            b_radius = b_map.get(asset.asset_id)
            pqc_rec = p_map.get(asset.asset_id)

            for ctrl in sorted_controls:
                assessments.append(
                    self.assess_asset_against_control(
                        asset=asset,
                        control=ctrl,
                        framework_applicability=applicability,
                        quantum_risk=q_risk,
                        blast_radius=b_radius,
                        pqc_rec=pqc_rec,
                    )
                )

        # Count status totals
        aligned_count = sum(1 for a in assessments if a.status == ComplianceStatus.ALIGNED)
        req_att_count = sum(1 for a in assessments if a.status == ComplianceStatus.REQUIRES_ATTENTION)
        gap_count = sum(1 for a in assessments if a.status == ComplianceStatus.GAP)
        na_count = sum(1 for a in assessments if a.status == ComplianceStatus.NOT_APPLICABLE)
        unk_count = sum(1 for a in assessments if a.status == ComplianceStatus.UNKNOWN)

        # Score calculation: aligned / applicable_controls
        applicable_total = aligned_count + req_att_count + gap_count
        if applicable_total > 0:
            score = (aligned_count / applicable_total) * 100.0
        else:
            score = 100.0 if applicability == PolicyApplicability.NOT_APPLICABLE else 0.0

        return FrameworkComplianceResult(
            framework_id=framework.framework_id,
            framework_name=framework.name,
            applicability=applicability,
            alignment_score=score,
            total_assessments=len(assessments),
            aligned_count=aligned_count,
            requires_attention_count=req_att_count,
            gap_count=gap_count,
            not_applicable_count=na_count,
            unknown_count=unk_count,
            assessments=tuple(assessments),
        )
