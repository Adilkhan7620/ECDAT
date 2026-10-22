"""End-to-end ECDAT Analysis Pipeline Orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from scanner.models import (
    AssetGroup,
    BlastRadiusAssessment,
    BlastRadiusLevel,
    BusinessAssetMapping,
    BusinessContext,
    CanonicalFinding,
    ClassifiedCryptoAsset,
    ComplianceAssessment,
    ComplianceFramework,
    CryptoClassification,
    EvidenceConfidence,
    FrameworkComplianceResult,
    MigrationPriority,
    PqcMigrationRecommendation,
    QuantumRiskAssessment,
    RiskLevel,
    ScannerResult,
    UnifiedCryptoAsset,
)
from scanner.normalizer import (
    AssetGrouper,
    ConfidenceClassifier,
    CorrelationEngine,
    FindingNormalizer,
)
from scanner.orchestrator import ScanOrchestrator
from scanner.pipeline.models import AnalysisSummary, EcdatAnalysisResult
from scanner.policy import CompliancePolicyEngine
from scanner.risk import BlastRadiusEngine, PqcRecommendationEngine, QuantumRiskEngine
from scanner.scanners import (
    GitleaksScanner,
    OpenSSLScanner,
    SemgrepScanner,
    SyftScanner,
    TrivyScanner,
)

logger = logging.getLogger(__name__)


def build_default_orchestrator() -> ScanOrchestrator:
    """Build scan orchestrator with default scanner suite."""
    return ScanOrchestrator(
        [
            SemgrepScanner(),
            GitleaksScanner(),
            SyftScanner(),
            TrivyScanner(),
            OpenSSLScanner(),
        ]
    )


class EcdatAnalysisPipeline:
    """End-to-end pipeline orchestrator connecting discovery and analysis engines."""

    def __init__(
        self,
        scan_orchestrator: Optional[ScanOrchestrator] = None,
        normalizer: Optional[FindingNormalizer] = None,
        asset_grouper: Optional[AssetGrouper] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        confidence_classifier: Optional[ConfidenceClassifier] = None,
        quantum_risk_engine: Optional[QuantumRiskEngine] = None,
        blast_radius_engine: Optional[BlastRadiusEngine] = None,
        pqc_recommendation_engine: Optional[PqcRecommendationEngine] = None,
        compliance_engine: Optional[CompliancePolicyEngine] = None,
    ) -> None:
        self.scan_orchestrator = scan_orchestrator or build_default_orchestrator()
        self.normalizer = normalizer or FindingNormalizer()
        self.asset_grouper = asset_grouper or AssetGrouper()
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.confidence_classifier = confidence_classifier or ConfidenceClassifier()
        self.quantum_risk_engine = quantum_risk_engine or QuantumRiskEngine()
        self.blast_radius_engine = blast_radius_engine or BlastRadiusEngine()
        self.pqc_recommendation_engine = (
            pqc_recommendation_engine or PqcRecommendationEngine()
        )
        self.compliance_engine = compliance_engine or CompliancePolicyEngine()

    def analyze(
        self,
        target: Union[str, Path],
        scanner_selection: Optional[Sequence[str]] = None,
        business_context: Optional[BusinessContext] = None,
        business_mappings: Optional[List[BusinessAssetMapping]] = None,
        data_lifetime_years: Optional[float] = None,
        migration_time_years: Optional[float] = None,
        years_until_crqc: Optional[float] = None,
        compliance_frameworks: Optional[List[Union[str, ComplianceFramework]]] = None,
    ) -> EcdatAnalysisResult:
        """Execute the end-to-end analysis pipeline deterministically."""
        target_path = Path(target)
        result = EcdatAnalysisResult()
        result.metadata = {
            "target": str(target_path.resolve()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner_selection": list(scanner_selection) if scanner_selection else "ALL",
            "data_lifetime_years": data_lifetime_years,
            "migration_time_years": migration_time_years,
            "years_until_crqc": years_until_crqc,
        }

        # Stage 1: Scanner Discovery
        try:
            scan_results = self.scan_orchestrator.scan(target_path, scanner_selection)
            # Sort scan_results deterministically by scanner
            result.scan_results = sorted(scan_results, key=lambda r: r.scanner)

            failed_scanners = [r for r in result.scan_results if r.status.value == "failed"]
            if failed_scanners and len(failed_scanners) == len(result.scan_results):
                result.stage_status["discovery"] = "FAILED"
            elif failed_scanners:
                result.stage_status["discovery"] = "PARTIAL"
            else:
                result.stage_status["discovery"] = "SUCCESS"

            for r in result.scan_results:
                if r.status.value == "failed":
                    result.errors.append(
                        {
                            "stage": "discovery",
                            "scanner": r.scanner,
                            "error": r.message,
                        }
                    )
        except Exception as exc:
            logger.exception("Scanner discovery failed")
            result.stage_status["discovery"] = "FAILED"
            result.errors.append({"stage": "discovery", "error": str(exc)})
            result.scan_results = []

        # Stage 2: Finding Normalization
        try:
            all_canonical: List[CanonicalFinding] = []
            for scan_res in result.scan_results:
                if scan_res.status.value == "completed" and scan_res.findings:
                    canonical_list = self.normalizer.normalize(scan_res.findings)
                    all_canonical.extend(canonical_list)

            # Sort canonical findings deterministically by finding_id
            result.canonical_findings = sorted(all_canonical, key=lambda f: f.finding_id)
            result.stage_status["normalization"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Finding normalization failed")
            result.stage_status["normalization"] = "FAILED"
            result.errors.append({"stage": "normalization", "error": str(exc)})
            result.canonical_findings = []

        # Stage 3: Asset Identity & Grouping
        try:
            groups = self.asset_grouper.group(result.canonical_findings)
            # Sort asset groups deterministically by asset_id
            result.asset_groups = sorted(groups, key=lambda g: g.asset_id)
            result.stage_status["asset_identity"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Asset identity grouping failed")
            result.stage_status["asset_identity"] = "FAILED"
            result.errors.append({"stage": "asset_identity", "error": str(exc)})
            result.asset_groups = []

        # Stage 4: Evidence Correlation Engine
        try:
            correlation_res = self.correlation_engine.correlate(result.canonical_findings)
            # Sort unified assets deterministically by asset_id
            result.unified_assets = sorted(correlation_res.unified_assets, key=lambda a: a.asset_id)
            result.stage_status["correlation"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Correlation engine failed")
            result.stage_status["correlation"] = "FAILED"
            result.errors.append({"stage": "correlation", "error": str(exc)})
            result.unified_assets = []

        # Stage 5: Confidence & Cryptographic Classification
        try:
            classified = list(self.confidence_classifier.classify(correlation_res))
            # Sort classified assets deterministically by asset_id
            result.classified_assets = sorted(classified, key=lambda c: c.asset_id)
            result.stage_status["classification"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Confidence classification failed")
            result.stage_status["classification"] = "FAILED"
            result.errors.append({"stage": "classification", "error": str(exc)})
            result.classified_assets = []

        # Stage 6: Quantum Risk Engine
        try:
            kw_args: Dict[str, Any] = {}
            if data_lifetime_years is not None:
                kw_args["data_lifetime_years"] = data_lifetime_years
            if migration_time_years is not None:
                kw_args["migration_time_years"] = migration_time_years
            if years_until_crqc is not None:
                kw_args["years_until_crqc"] = years_until_crqc

            q_assessments = [
                self.quantum_risk_engine.assess(classified_asset, **kw_args)
                for classified_asset in result.classified_assets
            ]
            result.quantum_risk_assessments = sorted(q_assessments, key=lambda q: q.asset_id)
            result.stage_status["quantum_risk"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Quantum risk engine failed")
            result.stage_status["quantum_risk"] = "FAILED"
            result.errors.append({"stage": "quantum_risk", "error": str(exc)})
            result.quantum_risk_assessments = []

        # Maps for quick lookup in subsequent stages
        q_map = {q.asset_id: q for q in result.quantum_risk_assessments}
        class_map = {c.asset_id: c for c in result.classified_assets}

        # Stage 7: Business Blast Radius Engine
        try:
            b_assessments = [
                self.blast_radius_engine.assess(
                    asset=classified_asset,
                    business_contexts=business_context or (),
                    mappings=business_mappings or (),
                    quantum_risk=q_map.get(classified_asset.asset_id),
                )
                for classified_asset in result.classified_assets
            ]
            result.blast_radius_assessments = sorted(b_assessments, key=lambda b: b.asset_id)
            result.stage_status["blast_radius"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Blast radius engine failed")
            result.stage_status["blast_radius"] = "FAILED"
            result.errors.append({"stage": "blast_radius", "error": str(exc)})
            result.blast_radius_assessments = []

        b_map = {b.asset_id: b for b in result.blast_radius_assessments}

        # Stage 8: PQC Recommendation Engine
        try:
            p_recommendations: List[PqcMigrationRecommendation] = []
            for classified_asset in result.classified_assets:
                aid = classified_asset.asset_id
                q_ass = q_map.get(aid)
                b_ass = b_map.get(aid)
                rec = self.pqc_recommendation_engine.recommend(
                    asset=classified_asset,
                    quantum_risk=q_ass,
                    blast_radius=b_ass,
                )
                p_recommendations.append(rec)

            result.pqc_recommendations = sorted(p_recommendations, key=lambda p: p.asset_id)
            result.stage_status["pqc_recommendation"] = "SUCCESS"
        except Exception as exc:
            logger.exception("PQC recommendation engine failed")
            result.stage_status["pqc_recommendation"] = "FAILED"
            result.errors.append({"stage": "pqc_recommendation", "error": str(exc)})
            result.pqc_recommendations = []

        p_map = {p.asset_id: p for p in result.pqc_recommendations}

        # Stage 9: Compliance & Policy Mapping Engine
        try:
            framework_names = (
                [fw.value if isinstance(fw, ComplianceFramework) else fw for fw in compliance_frameworks]
                if compliance_frameworks
                else ["DST-NQM", "RBI-QSAFE", "CNSA-2.0"]
            )

            fw_evals: List[FrameworkComplianceResult] = []
            comp_assessments: List[ComplianceAssessment] = []
            for fw_id in framework_names:
                fw_res = self.compliance_engine.evaluate_framework(
                    framework_id=fw_id,
                    assets=result.classified_assets,
                    quantum_risks=result.quantum_risk_assessments,
                    blast_radii=result.blast_radius_assessments,
                    pqc_recs=result.pqc_recommendations,
                )
                fw_evals.append(fw_res)
                comp_assessments.extend(fw_res.assessments)

            result.compliance_results = sorted(
                comp_assessments, key=lambda c: (c.asset_id, c.framework_id, c.control_id)
            )
            result.framework_compliance_results = sorted(
                fw_evals, key=lambda f: f.framework_id
            )
            result.stage_status["compliance"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Compliance engine failed")
            result.stage_status["compliance"] = "FAILED"
            result.errors.append({"stage": "compliance", "error": str(exc)})
            result.compliance_results = []
            result.framework_compliance_results = []

        # Stage 10: Aggregate Summary & Top Priority Assets
        try:
            result.summary = self._compute_summary(result)
            result.top_priority_assets = self._compute_top_priority_assets(result, p_map)
            result.stage_status["final_summary"] = "SUCCESS"
        except Exception as exc:
            logger.exception("Final summary computation failed")
            result.stage_status["final_summary"] = "FAILED"
            result.errors.append({"stage": "final_summary", "error": str(exc)})

        return result

    def _compute_summary(self, result: EcdatAnalysisResult) -> AnalysisSummary:
        """Compute aggregate counts strictly from actual pipeline results."""
        total_scanner_findings = sum(
            len(r.findings) for r in result.scan_results if r.findings
        )
        total_canonical_findings = len(result.canonical_findings)
        total_assets = len(result.unified_assets)

        high_confidence_assets = sum(
            1
            for c in result.classified_assets
            if c.confidence.value == EvidenceConfidence.HIGH.value
        )

        quantum_critical_count = sum(
            1
            for q in result.quantum_risk_assessments
            if q.risk_level.value == RiskLevel.CRITICAL.value
        )
        quantum_high_count = sum(
            1
            for q in result.quantum_risk_assessments
            if q.risk_level.value == RiskLevel.HIGH.value
        )
        hndl_high_count = sum(
            1 for q in result.quantum_risk_assessments if q.hndl_exposure == "HIGH"
        )

        critical_blast_radius_count = sum(
            1
            for b in result.blast_radius_assessments
            if b.blast_radius_level.value == BlastRadiusLevel.CRITICAL.value
        )

        p0_count = sum(
            1
            for p in result.pqc_recommendations
            if p.migration_priority.value == MigrationPriority.P0.value
        )
        p1_count = sum(
            1
            for p in result.pqc_recommendations
            if p.migration_priority.value == MigrationPriority.P1.value
        )

        pqc_migration_required_count = sum(
            1 for p in result.pqc_recommendations if p.recommended_algorithm is not None
        )

        compliance_attention_count = sum(
            1
            for c in result.compliance_results
            if c.status.value == "REQUIRES_ATTENTION"
        )
        compliance_gap_count = sum(
            1
            for c in result.compliance_results
            if c.status.value == "GAP"
        )

        return AnalysisSummary(
            total_scanner_findings=total_scanner_findings,
            total_canonical_findings=total_canonical_findings,
            total_assets=total_assets,
            high_confidence_assets=high_confidence_assets,
            quantum_critical_count=quantum_critical_count,
            quantum_high_count=quantum_high_count,
            hndl_high_count=hndl_high_count,
            critical_blast_radius_count=critical_blast_radius_count,
            p0_count=p0_count,
            p1_count=p1_count,
            pqc_migration_required_count=pqc_migration_required_count,
            compliance_attention_count=compliance_attention_count,
            compliance_gap_count=compliance_gap_count,
        )

    def _compute_top_priority_assets(
        self,
        result: EcdatAnalysisResult,
        p_map: Dict[str, PqcMigrationRecommendation],
    ) -> List[Dict[str, Any]]:
        """Order top priority assets deterministically P0 -> P1 -> P2 -> P3 -> MONITOR, tie-broken by asset_id."""
        priority_rank = {
            MigrationPriority.P0.value: 0,
            MigrationPriority.P1.value: 1,
            MigrationPriority.P2.value: 2,
            MigrationPriority.P3.value: 3,
            MigrationPriority.MONITOR.value: 4,
        }

        items: List[Dict[str, Any]] = []
        for asset in result.unified_assets:
            aid = asset.asset_id
            rec = p_map.get(aid)
            p_val = rec.migration_priority.value if rec else MigrationPriority.MONITOR.value
            rank = priority_rank.get(p_val, 99)
            items.append(
                {
                    "rank": rank,
                    "asset_id": aid,
                    "priority": p_val,
                    "canonical_name": asset.canonical_name,
                    "asset_type": asset.asset_type,
                    "target_pqc_algorithm": rec.recommended_algorithm if (rec and rec.recommended_algorithm) else "NONE",
                    "migration_strategy": (
                        rec.migration_strategy.value if rec else "RETAIN_UNTIL_DEPRECATED"
                    ),
                }
            )

        # Sort by rank ascending, then asset_id ascending
        items.sort(key=lambda x: (x["rank"], x["asset_id"]))

        # Remove temporary sorting rank key from final output
        for item in items:
            del item["rank"]

        return items
