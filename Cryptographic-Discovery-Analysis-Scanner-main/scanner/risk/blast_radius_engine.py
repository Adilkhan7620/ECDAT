"""Business Blast Radius Engine implementation for ECDAT."""

from __future__ import annotations

from typing import Sequence

from scanner.models.blast_radius import (
    BlastRadiusAssessment,
    BlastRadiusLevel,
    BusinessAssetMapping,
    BusinessContext,
    BusinessCriticality,
    DataClassification,
)
from scanner.models.classified_asset import ClassifiedCryptoAsset
from scanner.models.quantum_risk import QuantumRiskAssessment


class BlastRadiusEngine:
    """Deterministic, rule-based Business Blast Radius Engine for ECDAT discovery assets.

    Evaluates application criticality, data classification, internet exposure, regulatory scope, and service reach.
    """

    CRITICALITY_SCORES: dict[BusinessCriticality, float] = {
        BusinessCriticality.CRITICAL: 40.0,
        BusinessCriticality.HIGH: 30.0,
        BusinessCriticality.MEDIUM: 20.0,
        BusinessCriticality.LOW: 10.0,
        BusinessCriticality.UNKNOWN: 0.0,
    }

    DATA_SCORES: dict[DataClassification, float] = {
        DataClassification.RESTRICTED: 30.0,
        DataClassification.CONFIDENTIAL: 20.0,
        DataClassification.INTERNAL: 10.0,
        DataClassification.PUBLIC: 0.0,
        DataClassification.UNKNOWN: 0.0,
    }

    def assess(
        self,
        asset: ClassifiedCryptoAsset,
        business_contexts: Sequence[BusinessContext] = (),
        mappings: Sequence[BusinessAssetMapping] = (),
        quantum_risk: QuantumRiskAssessment | None = None,
    ) -> BlastRadiusAssessment:
        """Perform a blast radius assessment for a single ClassifiedCryptoAsset."""
        asset_id = asset.asset_id

        # 1. Filter explicit mappings for this asset
        relevant_mappings = tuple(sorted([m for m in mappings if m.asset_id == asset_id], key=lambda m: (m.application_id, m.service_name or "")))

        # Find matching business contexts
        context_map: dict[str, BusinessContext] = {ctx.application_id: ctx for ctx in business_contexts}

        # Deduplicate affected applications, services, business functions, data classifications, and regulatory scopes
        apps_set: set[str] = set()
        services_set: set[str] = set()
        functions_set: set[str] = set()
        data_classes_set: set[DataClassification] = set()
        reg_scopes_set: set[str] = set()

        max_criticality = BusinessCriticality.UNKNOWN
        max_data_class = DataClassification.UNKNOWN
        is_internet_exposed: bool | None = None
        has_explicit_context = False

        factors: list[str] = []

        for m in relevant_mappings:
            has_explicit_context = True
            app_id = m.application_id
            apps_set.add(app_id)

            if m.service_name:
                services_set.add(m.service_name)
            if m.business_function:
                functions_set.add(m.business_function)

            # Update criticality & data class from mapping
            if self.CRITICALITY_SCORES[m.criticality] > self.CRITICALITY_SCORES[max_criticality]:
                max_criticality = m.criticality
            if self.DATA_SCORES[m.data_classification] > self.DATA_SCORES[max_data_class]:
                max_data_class = m.data_classification
            if m.data_classification != DataClassification.UNKNOWN:
                data_classes_set.add(m.data_classification)

            # Check matching BusinessContext
            ctx = context_map.get(app_id)
            if ctx:
                if ctx.application_name:
                    apps_set.add(ctx.application_name)
                if ctx.service_name:
                    services_set.add(ctx.service_name)
                if ctx.business_function:
                    functions_set.add(ctx.business_function)
                if self.CRITICALITY_SCORES[ctx.criticality] > self.CRITICALITY_SCORES[max_criticality]:
                    max_criticality = ctx.criticality
                if self.DATA_SCORES[ctx.data_classification] > self.DATA_SCORES[max_data_class]:
                    max_data_class = ctx.data_classification
                if ctx.data_classification != DataClassification.UNKNOWN:
                    data_classes_set.add(ctx.data_classification)
                if ctx.internet_exposed is True:
                    is_internet_exposed = True
                elif ctx.internet_exposed is False and is_internet_exposed is None:
                    is_internet_exposed = False
                if ctx.regulatory_scope:
                    reg_scopes_set.add(ctx.regulatory_scope)

        # Check if asset metadata specifies internet exposure directly if context didn't
        if is_internet_exposed is None and asset.metadata.get("internet_exposed") is True:
            is_internet_exposed = True

        # Handle missing business context
        if not has_explicit_context and not relevant_mappings and not apps_set:
            factors.append("Missing explicit business context mapping for asset")
            rationale = "Business context mapping is unavailable; blast radius cannot be reliably evaluated."
            return BlastRadiusAssessment(
                asset_id=asset_id,
                blast_radius_level=BlastRadiusLevel.UNKNOWN,
                impact_score=0.0,
                affected_applications=(),
                affected_services=(),
                affected_business_functions=(),
                affected_data_classifications=(),
                criticality=BusinessCriticality.UNKNOWN,
                internet_exposed=None,
                regulatory_scopes=(),
                quantum_risk=quantum_risk,
                rationale=rationale,
                contributing_factors=tuple(factors),
            )

        # 2. Score Calculation
        score = 0.0

        # Criticality contribution (max 40 pts)
        crit_score = self.CRITICALITY_SCORES[max_criticality]
        score += crit_score
        if max_criticality != BusinessCriticality.UNKNOWN:
            factors.append(f"Application criticality: {max_criticality.value} (+{crit_score:.0f} pts)")

        # Data classification contribution (max 30 pts)
        data_score = self.DATA_SCORES[max_data_class]
        score += data_score
        if max_data_class != DataClassification.UNKNOWN:
            factors.append(f"Data sensitivity: {max_data_class.value} (+{data_score:.0f} pts)")

        # Application / Service reach contribution (max 15 pts)
        app_count = len(apps_set)
        svc_count = len(services_set)
        reach_score = min(15.0, (app_count * 5.0) + (svc_count * 2.0))
        score += reach_score
        if app_count > 0 or svc_count > 0:
            factors.append(f"System reach: {app_count} application(s), {svc_count} service(s) (+{reach_score:.0f} pts)")

        # Internet exposure contribution (10 pts)
        if is_internet_exposed is True:
            score += 10.0
            factors.append("Internet exposure: Exposed to public internet (+10 pts)")

        # Regulatory scope contribution (5 pts)
        if reg_scopes_set:
            score += 5.0
            scopes_str = ", ".join(sorted(reg_scopes_set))
            factors.append(f"Regulatory scope: {scopes_str} (+5 pts)")

        # Cap impact score at 100.0
        final_score = min(100.0, score)

        # Determine BlastRadiusLevel
        if final_score >= 80.0 or max_criticality == BusinessCriticality.CRITICAL:
            level = BlastRadiusLevel.CRITICAL
        elif final_score >= 60.0:
            level = BlastRadiusLevel.LARGE
        elif final_score >= 35.0:
            level = BlastRadiusLevel.MEDIUM
        else:
            level = BlastRadiusLevel.SMALL

        # Build Rationale
        sorted_apps = tuple(sorted(apps_set))
        sorted_svcs = tuple(sorted(services_set))
        sorted_funcs = tuple(sorted(functions_set))
        sorted_data = tuple(sorted(data_classes_set, key=lambda d: self.DATA_SCORES[d], reverse=True))
        sorted_scopes = tuple(sorted(reg_scopes_set))

        rationale_parts = [
            f"Asset is mapped to {len(sorted_apps)} application(s) ({', '.join(sorted_apps)}) and {len(sorted_svcs)} service(s)."
        ]
        if max_criticality != BusinessCriticality.UNKNOWN:
            rationale_parts.append(f"Peak business criticality is {max_criticality.value}.")
        if max_data_class != DataClassification.UNKNOWN:
            rationale_parts.append(f"Peak data sensitivity is {max_data_class.value}.")
        if is_internet_exposed is True:
            rationale_parts.append("Asset is exposed to the public internet.")
        if sorted_scopes:
            rationale_parts.append(f"Subject to regulatory scope(s): {', '.join(sorted_scopes)}.")

        rationale_parts.append(f"Overall assessed blast radius is {level.value} (impact score: {final_score:.1f}/100).")
        rationale = " ".join(rationale_parts)

        return BlastRadiusAssessment(
            asset_id=asset_id,
            blast_radius_level=level,
            impact_score=final_score,
            affected_applications=sorted_apps,
            affected_services=sorted_svcs,
            affected_business_functions=sorted_funcs,
            affected_data_classifications=sorted_data,
            criticality=max_criticality,
            internet_exposed=is_internet_exposed,
            regulatory_scopes=sorted_scopes,
            quantum_risk=quantum_risk,
            rationale=rationale,
            contributing_factors=tuple(factors),
        )

    def assess_batch(
        self,
        assets: Sequence[ClassifiedCryptoAsset],
        business_contexts: Sequence[BusinessContext] = (),
        mappings: Sequence[BusinessAssetMapping] = (),
        quantum_risks: Sequence[QuantumRiskAssessment] | None = None,
    ) -> tuple[BlastRadiusAssessment, ...]:
        """Assess a batch of ClassifiedCryptoAsset objects deterministically in input order."""
        risk_map: dict[str, QuantumRiskAssessment] = {}
        if quantum_risks:
            risk_map = {r.asset_id: r for r in quantum_risks}

        assessments: list[BlastRadiusAssessment] = []
        for asset in assets:
            q_risk = risk_map.get(asset.asset_id)
            assessments.append(
                self.assess(
                    asset=asset,
                    business_contexts=business_contexts,
                    mappings=mappings,
                    quantum_risk=q_risk,
                )
            )
        return tuple(assessments)
