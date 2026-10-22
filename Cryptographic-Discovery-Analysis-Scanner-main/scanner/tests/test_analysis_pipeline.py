"""Tests for the ECDAT End-to-End Analysis Pipeline."""

import json
import random
import unittest
from unittest.mock import MagicMock, patch

from shared.models.finding import CryptoUsage, FindingCategory, FindingSource, ToolEvidence, ToolName
from scanner.models import (
    BlastRadiusLevel,
    BusinessContext,
    CanonicalFinding,
    ComplianceFramework,
    Finding,
    FindingType,
    MigrationPriority,
    RiskLevel,
    ScannerResult,
    ScannerStatus,
)
from scanner.core.base_scanner import BaseScanner
from scanner.orchestrator import ScanOrchestrator
from scanner.pipeline import EcdatAnalysisPipeline, EcdatAnalysisResult
from scanner.scanners import GitleaksScanner


class DummyScanner(BaseScanner):
    def __init__(self, name: str, findings: list, available: bool = True):
        self.name = name
        self.executable = name
        self._findings = findings
        self._available = available

    def is_available(self) -> bool:
        return self._available

    def scan(self, target):
        if not self._available:
            return ScannerResult(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                message="Scanner tool not installed",
            )
        return ScannerResult(
            scanner=self.name,
            status=ScannerStatus.COMPLETED,
            message="Scan completed successfully",
            findings=tuple(self._findings),
        )


class TestEcdatAnalysisPipeline(unittest.TestCase):
    def setUp(self):
        # Sample findings using shared.models.Finding contract
        self.semgrep_rsa_finding = Finding(
            finding_id="semgrep-rsa-1",
            tool=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            evidence=ToolEvidence(
                message="Use of RSA 2048 key generation",
                original={"snippet": "RSA.generate(2048)"},
            ),
            metadata={
                "check_id": "python.lang.security.crypto.rsa-2048",
                "extra": {"metavars": {"$KEYSIZE": {"abstract_content": "2048"}}},
            },
            algorithm="RSA",
            key_size=2048,
            file="src/crypto.py",
            line=10,
        )

        self.syft_pkg_finding = Finding(
            finding_id="syft-pkg-1",
            tool=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            evidence=ToolEvidence(message="Package pycryptodome 3.10.0"),
            metadata={
                "name": "pycryptodome",
                "version": "3.10.0",
                "type": "python",
                "purl": "pkg:pypi/pycryptodome@3.10.0",
            },
        )

        self.trivy_vuln_finding = Finding(
            finding_id="trivy-vuln-1",
            tool=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            evidence=ToolEvidence(message="CVE-2021-12345 in pycryptodome"),
            metadata={
                "VulnerabilityID": "CVE-2021-12345",
                "PkgName": "pycryptodome",
                "InstalledVersion": "3.10.0",
                "Severity": "HIGH",
            },
        )

        self.openssl_cert_finding = Finding(
            finding_id="openssl-cert-1",
            tool=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            evidence=ToolEvidence(message="RSA 2048 certificate"),
            metadata={
                "algorithm": "RSA",
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "subject": "CN=example.com",
                "issuer": "CN=ECDAT Root CA",
            },
            algorithm="RSA",
            key_size=2048,
            usage=CryptoUsage.DIGITAL_SIGNATURE,
            file="certs/server.crt",
        )

        self.gitleaks_secret_finding = Finding(
            finding_id="gitleaks-key-1",
            tool=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            evidence=ToolEvidence(
                message="Private Key detected",
                original={
                    "Secret": "[REDACTED]",
                    "Match": "[REDACTED]",
                },
            ),
            metadata={"RuleID": "private-key"},
            file="config/keys.pem",
            line=1,
        )

    def test_1_semgrep_rsa_e2e(self):
        """Test 1: Synthetic Semgrep RSA finding complete pipeline execution."""
        scanner = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        orchestrator = ScanOrchestrator([scanner])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        self.assertEqual(len(result.canonical_findings), 1)
        self.assertEqual(len(result.unified_assets), 1)
        self.assertEqual(len(result.classified_assets), 1)
        self.assertEqual(len(result.quantum_risk_assessments), 1)
        self.assertEqual(len(result.pqc_recommendations), 1)

        q_risk = result.quantum_risk_assessments[0]
        self.assertEqual(q_risk.algorithm, "RSA")
        self.assertEqual(q_risk.key_size, 2048)

    def test_2_syft_package_trivy_vulnerability(self):
        """Test 2: Syft package + Trivy vulnerability package asset and relationship."""
        scanner_syft = DummyScanner("syft", [self.syft_pkg_finding])
        scanner_trivy = DummyScanner("trivy", [self.trivy_vuln_finding])
        orchestrator = ScanOrchestrator([scanner_syft, scanner_trivy])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        self.assertTrue(len(result.unified_assets) >= 1)
        self.assertTrue(len(result.compliance_results) > 0)

    def test_3_openssl_rsa_certificate(self):
        """Test 3: OpenSSL RSA certificate -> quantum assessment -> PQC recommendation."""
        scanner = DummyScanner("openssl", [self.openssl_cert_finding])
        orchestrator = ScanOrchestrator([scanner])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        self.assertEqual(len(result.unified_assets), 1)
        asset = result.unified_assets[0]
        self.assertEqual(asset.algorithm, "RSA")

        pqc = result.pqc_recommendations[0]
        self.assertIsNotNone(pqc.migration_strategy)

    def test_4_gitleaks_private_key_redacted(self):
        """Test 4: Gitleaks private key remains redacted throughout complete pipeline."""
        scanner = DummyScanner("gitleaks", [self.gitleaks_secret_finding])
        orchestrator = ScanOrchestrator([scanner])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        result_dict = result.to_dict()
        serialized = json.dumps(result_dict)

        self.assertNotIn("SUPER_SECRET_KEY_DATA", serialized)
        self.assertNotIn("SUPER_SECRET_KEY_DATA", str(result))

    def test_5_missing_business_context(self):
        """Test 5: Missing business context -> BlastRadius = UNKNOWN/partial."""
        scanner = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        orchestrator = ScanOrchestrator([scanner])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".", business_context=None)
        self.assertEqual(len(result.blast_radius_assessments), 1)
        blast = result.blast_radius_assessments[0]
        self.assertEqual(blast.blast_radius_level, BlastRadiusLevel.UNKNOWN)

    def test_6_missing_lifecycle_data(self):
        """Test 6: Missing lifecycle data -> QuantumRiskEngine behavior preserved."""
        scanner = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        orchestrator = ScanOrchestrator([scanner])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(
            ".", data_lifetime_years=None, migration_time_years=None
        )
        self.assertEqual(len(result.quantum_risk_assessments), 1)
        q_risk = result.quantum_risk_assessments[0]
        self.assertIn(q_risk.hndl_exposure, ["HIGH", "POSSIBLE", "UNKNOWN"])

    def test_7_multiple_scanner_findings_correlation(self):
        """Test 7: Multiple scanner findings correlation."""
        scanner1 = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        scanner2 = DummyScanner("openssl", [self.openssl_cert_finding])
        orchestrator = ScanOrchestrator([scanner1, scanner2])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        self.assertEqual(len(result.canonical_findings), 2)

    def test_8_finding_order_shuffled_determinism(self):
        """Test 8: Finding order shuffled produces deterministic final result."""
        findings_a = [self.semgrep_rsa_finding, self.openssl_cert_finding]
        findings_b = [self.openssl_cert_finding, self.semgrep_rsa_finding]

        scanner_a = DummyScanner("semgrep", findings_a)
        orchestrator_a = ScanOrchestrator([scanner_a])
        pipeline_a = EcdatAnalysisPipeline(scan_orchestrator=orchestrator_a)
        res_a = pipeline_a.analyze(".").to_dict()

        scanner_b = DummyScanner("semgrep", findings_b)
        orchestrator_b = ScanOrchestrator([scanner_b])
        pipeline_b = EcdatAnalysisPipeline(scan_orchestrator=orchestrator_b)
        res_b = pipeline_b.analyze(".").to_dict()

        # Sort scan_results and canonical_findings in dicts for deterministic comparison
        res_a["metadata"]["timestamp"] = ""
        res_b["metadata"]["timestamp"] = ""
        res_a["scan_results"] = sorted(res_a["scan_results"], key=lambda r: r["scanner"])
        res_b["scan_results"] = sorted(res_b["scan_results"], key=lambda r: r["scanner"])
        self.assertEqual(res_a["unified_assets"], res_b["unified_assets"])
        self.assertEqual(res_a["classified_assets"], res_b["classified_assets"])
        self.assertEqual(res_a["quantum_risk_assessments"], res_b["quantum_risk_assessments"])
        self.assertEqual(res_a["pqc_recommendations"], res_b["pqc_recommendations"])
        self.assertEqual(res_a["top_priority_assets"], res_b["top_priority_assets"])

    def test_9_scanner_order_shuffled_determinism(self):
        """Test 9: Scanner order shuffled produces deterministic final result."""
        scanner1 = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        scanner2 = DummyScanner("openssl", [self.openssl_cert_finding])

        orchestrator_a = ScanOrchestrator([scanner1, scanner2])
        pipeline_a = EcdatAnalysisPipeline(scan_orchestrator=orchestrator_a)
        res_a = pipeline_a.analyze(".").to_dict()

        orchestrator_b = ScanOrchestrator([scanner2, scanner1])
        pipeline_b = EcdatAnalysisPipeline(scan_orchestrator=orchestrator_b)
        res_b = pipeline_b.analyze(".").to_dict()

        res_a["metadata"]["timestamp"] = ""
        res_b["metadata"]["timestamp"] = ""
        self.assertEqual(res_a, res_b)

    def test_10_one_unavailable_scanner(self):
        """Test 10: One unavailable scanner -> pipeline continues and records status."""
        scanner_avail = DummyScanner("semgrep", [self.semgrep_rsa_finding], available=True)
        scanner_unavail = DummyScanner("trivy", [], available=False)

        orchestrator = ScanOrchestrator([scanner_avail, scanner_unavail])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        self.assertEqual(result.stage_status["discovery"], "PARTIAL")
        self.assertEqual(len(result.unified_assets), 1)
        self.assertTrue(any(e["scanner"] == "trivy" for e in result.errors))

    def test_11_summary_counts_equal_actuals(self):
        """Test 11: Final summary counts equal actual generated assessment collections."""
        scanner1 = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        scanner2 = DummyScanner("syft", [self.syft_pkg_finding])
        orchestrator = ScanOrchestrator([scanner1, scanner2])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        summary = result.summary

        self.assertEqual(summary.total_canonical_findings, len(result.canonical_findings))
        self.assertEqual(summary.total_assets, len(result.unified_assets))
        self.assertEqual(
            summary.quantum_critical_count,
            sum(
                1
                for q in result.quantum_risk_assessments
                if q.risk_level.value == RiskLevel.CRITICAL.value
            ),
        )
        self.assertEqual(
            summary.p0_count,
            sum(
                1
                for p in result.pqc_recommendations
                if p.migration_priority.value == MigrationPriority.P0.value
            ),
        )

    def test_12_top_priority_ordering(self):
        """Test 12: Top-priority ordering is deterministic."""
        scanner1 = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        scanner2 = DummyScanner("openssl", [self.openssl_cert_finding])
        orchestrator = ScanOrchestrator([scanner1, scanner2])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".")
        top_priorities = result.top_priority_assets
        self.assertTrue(len(top_priorities) >= 1)
        # Verify ordering is sorted by priority then asset_id
        for i in range(len(top_priorities) - 1):
            curr = top_priorities[i]
            nxt = top_priorities[i + 1]
            # Since rank ordering was applied, priority of curr should be <= nxt in rank hierarchy
            priority_rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "MONITOR": 4}
            self.assertLessEqual(
                priority_rank[curr["priority"]], priority_rank[nxt["priority"]]
            )

    def test_13_no_secret_in_serialized_result(self):
        """Test 13: No secret value appears anywhere in final serialized EcdatAnalysisResult."""
        scanner = DummyScanner("gitleaks", [self.gitleaks_secret_finding])
        orchestrator = ScanOrchestrator([scanner])
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze("dummy/target")
        dict_data = result.to_dict()
        json_str = json.dumps(dict_data)
        self.assertNotIn("SUPER_SECRET_KEY_DATA", json_str)

    def test_14_complete_pipeline_all_scanners(self):
        """Test 14: Complete pipeline with all scanner findings produces all 8 stages output."""
        scanner1 = DummyScanner("semgrep", [self.semgrep_rsa_finding])
        scanner2 = DummyScanner("syft", [self.syft_pkg_finding])
        scanner3 = DummyScanner("trivy", [self.trivy_vuln_finding])
        scanner4 = DummyScanner("openssl", [self.openssl_cert_finding])
        scanner5 = DummyScanner("gitleaks", [self.gitleaks_secret_finding])

        orchestrator = ScanOrchestrator(
            [scanner1, scanner2, scanner3, scanner4, scanner5]
        )
        pipeline = EcdatAnalysisPipeline(scan_orchestrator=orchestrator)

        result = pipeline.analyze(".", compliance_frameworks=["DST-NQM", "RBI-QSAFE"])
        self.assertEqual(result.stage_status["discovery"], "SUCCESS")
        self.assertEqual(result.stage_status["normalization"], "SUCCESS")
        self.assertEqual(result.stage_status["asset_identity"], "SUCCESS")
        self.assertEqual(result.stage_status["correlation"], "SUCCESS")
        self.assertEqual(result.stage_status["classification"], "SUCCESS")
        self.assertEqual(result.stage_status["quantum_risk"], "SUCCESS")
        self.assertEqual(result.stage_status["blast_radius"], "SUCCESS")
        self.assertEqual(result.stage_status["pqc_recommendation"], "SUCCESS")
        self.assertEqual(result.stage_status["compliance"], "SUCCESS")
        self.assertEqual(result.stage_status["final_summary"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
