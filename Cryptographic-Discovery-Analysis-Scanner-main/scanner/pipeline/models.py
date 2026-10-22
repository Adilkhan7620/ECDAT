"""Pipeline data models for the ECDAT End-to-End Analysis Pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from scanner.models import (
    AssetGroup,
    BlastRadiusAssessment,
    CanonicalFinding,
    ClassifiedCryptoAsset,
    ComplianceAssessment,
    FrameworkComplianceResult,
    MigrationPriority,
    PqcMigrationRecommendation,
    QuantumRiskAssessment,
    RiskLevel,
    ScannerResult,
    UnifiedCryptoAsset,
)


@dataclass
class AnalysisSummary:
    """Aggregate summary statistics derived strictly from actual pipeline results."""

    total_scanner_findings: int = 0
    total_canonical_findings: int = 0
    total_assets: int = 0
    high_confidence_assets: int = 0
    quantum_critical_count: int = 0
    quantum_high_count: int = 0
    hndl_high_count: int = 0
    critical_blast_radius_count: int = 0
    p0_count: int = 0
    p1_count: int = 0
    pqc_migration_required_count: int = 0
    compliance_attention_count: int = 0
    compliance_gap_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AnalysisSummary to a dictionary."""
        return {
            "total_scanner_findings": self.total_scanner_findings,
            "total_canonical_findings": self.total_canonical_findings,
            "total_assets": self.total_assets,
            "high_confidence_assets": self.high_confidence_assets,
            "quantum_critical_count": self.quantum_critical_count,
            "quantum_high_count": self.quantum_high_count,
            "hndl_high_count": self.hndl_high_count,
            "critical_blast_radius_count": self.critical_blast_radius_count,
            "p0_count": self.p0_count,
            "p1_count": self.p1_count,
            "pqc_migration_required_count": self.pqc_migration_required_count,
            "compliance_attention_count": self.compliance_attention_count,
            "compliance_gap_count": self.compliance_gap_count,
        }


@dataclass
class EcdatAnalysisResult:
    """Complete end-to-end analysis result containing structured pipeline outputs."""

    scan_results: List[ScannerResult] = field(default_factory=list)
    canonical_findings: List[CanonicalFinding] = field(default_factory=list)
    asset_groups: List[AssetGroup] = field(default_factory=list)
    unified_assets: List[UnifiedCryptoAsset] = field(default_factory=list)
    classified_assets: List[ClassifiedCryptoAsset] = field(default_factory=list)
    quantum_risk_assessments: List[QuantumRiskAssessment] = field(default_factory=list)
    blast_radius_assessments: List[BlastRadiusAssessment] = field(default_factory=list)
    pqc_recommendations: List[PqcMigrationRecommendation] = field(default_factory=list)
    compliance_results: List[ComplianceAssessment] = field(default_factory=list)
    framework_compliance_results: List[FrameworkComplianceResult] = field(default_factory=list)
    summary: AnalysisSummary = field(default_factory=AnalysisSummary)
    top_priority_assets: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    stage_status: Dict[str, str] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete analysis result to sanitized dictionary."""
        return {
            "scan_results": [r.to_dict() for r in self.scan_results],
            "canonical_findings": [f.to_dict() for f in self.canonical_findings],
            "asset_groups": [g.to_dict() for g in self.asset_groups],
            "unified_assets": [a.to_dict() for a in self.unified_assets],
            "classified_assets": [c.to_dict() for c in self.classified_assets],
            "quantum_risk_assessments": [q.to_dict() for q in self.quantum_risk_assessments],
            "blast_radius_assessments": [b.to_dict() for b in self.blast_radius_assessments],
            "pqc_recommendations": [p.to_dict() for p in self.pqc_recommendations],
            "compliance_results": [c.to_dict() for c in self.compliance_results],
            "framework_compliance_results": [
                f.to_dict() for f in self.framework_compliance_results
            ],
            "summary": self.summary.to_dict(),
            "top_priority_assets": self.top_priority_assets,
            "metadata": self.metadata,
            "stage_status": self.stage_status,
            "errors": self.errors,
        }
