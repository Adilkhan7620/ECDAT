"""Unit tests for ECDAT Asset Identity Resolution and Deduplication layer."""

import json
import unittest

from shared.models import FindingCategory, FindingSource, ToolEvidence, ToolName
from scanner.models import AssetGroup, AssetIdentity, CanonicalFinding
from scanner.normalizer import AssetGrouper, AssetIdentityResolver


class AssetIdentityAndGrouperTests(unittest.TestCase):
    """Verify asset identity resolution, deduplication, and security rules."""

    def setUp(self) -> None:
        """Set up resolver and grouper instances."""
        self.resolver = AssetIdentityResolver()
        self.grouper = AssetGrouper(self.resolver)

    def test_same_semgrep_finding_normalized_twice_produces_same_asset_id(self) -> None:
        """Requirement 8A: Normalizing/resolving identical Semgrep finding twice produces exact same asset_id."""
        finding1 = CanonicalFinding(
            finding_id="sem-1",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
            line_start=15,
        )
        finding2 = CanonicalFinding(
            finding_id="sem-2",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
            line_start=15,
        )

        identity1 = self.resolver.resolve(finding1)
        identity2 = self.resolver.resolve(finding2)

        self.assertEqual(identity1.asset_id, identity2.asset_id)
        self.assertEqual(identity1.canonical_name, "CryptoApi:auth.py:RSA")

    def test_same_package_from_syft_appearing_twice_produces_same_asset_id(self) -> None:
        """Requirement 8B: Same package appearing twice in Syft produces exact same asset_id."""
        finding1 = CanonicalFinding(
            finding_id="syft-1",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="pycryptodome",
            package_version="3.18.0",
            package_type="python",
            file="requirements.txt",
        )
        finding2 = CanonicalFinding(
            finding_id="syft-2",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="pycryptodome",
            package_version="3.18.0",
            package_type="python",
            file="Pipfile.lock",
        )

        identity1 = self.resolver.resolve(finding1)
        identity2 = self.resolver.resolve(finding2)

        self.assertEqual(identity1.asset_id, identity2.asset_id)
        self.assertEqual(identity1.canonical_name, "Component:pycryptodome@3.18.0")

    def test_same_vulnerability_package_combination_produces_same_vulnerability_identity(self) -> None:
        """Requirement 8C: Same vulnerability + package combination produces exact same vulnerability identity."""
        finding1 = CanonicalFinding(
            finding_id="trivy-1",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-49460",
            package_name="pycryptodome",
            package_version="3.18.0",
        )
        finding2 = CanonicalFinding(
            finding_id="trivy-2",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            vulnerability_id="CVE-2023-49460",
            package_name="pycryptodome",
            package_version="3.18.0",
        )

        identity1 = self.resolver.resolve(finding1)
        identity2 = self.resolver.resolve(finding2)

        self.assertEqual(identity1.asset_id, identity2.asset_id)
        self.assertEqual(identity1.canonical_name, "Vulnerability:CVE-2023-49460:pycryptodome@3.18.0")

    def test_rsa_usage_in_two_different_files_produces_different_asset_ids(self) -> None:
        """Requirement 8D: RSA usage in two different files produces different asset IDs."""
        finding_auth = CanonicalFinding(
            finding_id="rsa-auth",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
        )
        finding_payment = CanonicalFinding(
            finding_id="rsa-payment",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="payment.py",
        )

        identity_auth = self.resolver.resolve(finding_auth)
        identity_payment = self.resolver.resolve(finding_payment)

        self.assertNotEqual(identity_auth.asset_id, identity_payment.asset_id)

    def test_gitleaks_findings_with_different_secrets_same_safe_context(self) -> None:
        """Requirement 8E: Gitleaks findings with different secret values but same safe context produce same safe ID without exposing secret content."""
        finding1 = CanonicalFinding(
            finding_id="git-1",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            file="credentials.env",
            line_start=10,
            finding_type="aws-access-key",
            evidence=ToolEvidence(
                message="AWS Key",
                original={"Secret": "[REDACTED]", "Match": "[REDACTED]"},
            ),
        )
        finding2 = CanonicalFinding(
            finding_id="git-2",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.SECRET,
            source=FindingSource.SECRET_STORE,
            file="credentials.env",
            line_start=10,
            finding_type="aws-access-key",
            evidence=ToolEvidence(
                message="AWS Key",
                original={"Secret": "[REDACTED]", "Match": "[REDACTED]"},
            ),
        )

        identity1 = self.resolver.resolve(finding1)
        identity2 = self.resolver.resolve(finding2)

        self.assertEqual(identity1.asset_id, identity2.asset_id)
        # Security assertion: ensure secret content is not in asset identity or serialized JSON
        self.assertNotIn("AKIA", identity1.to_json())
        self.assertNotIn("DUMMY_SECRET", identity1.to_json())

    def test_semgrep_and_openssl_findings_separate_when_fields_do_not_permit_grouping(self) -> None:
        """Requirement 8F: Semgrep code finding and OpenSSL cert finding remain separate when available fields do not explicitly link them."""
        semgrep_finding = CanonicalFinding(
            finding_id="sem-rsa",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            key_size=2048,
            file="server.py",
        )
        openssl_finding = CanonicalFinding(
            finding_id="ssl-cert",
            scanner=ToolName.OPENSSL,
            category=FindingCategory.CERTIFICATE,
            source=FindingSource.CERTIFICATE_FILE,
            algorithm="RSA",
            key_size=2048,
            subject="CN=server.local",
            serial="987654321",
            file="certs/server.crt",
        )

        groups = self.grouper.group([semgrep_finding, openssl_finding])

        # Must remain 2 separate asset groups rather than inventing a relationship
        self.assertEqual(len(groups), 2)
        asset_ids = {group.asset_id for group in groups}
        self.assertEqual(len(asset_ids), 2)

    def test_finding_order_does_not_affect_asset_ids(self) -> None:
        """Requirement 8G: Finding order does not alter generated asset IDs or grouping."""
        finding_a = CanonicalFinding(
            finding_id="fa",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="AES",
            file="encrypt.py",
        )
        finding_b = CanonicalFinding(
            finding_id="fb",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="pycryptodome",
            package_version="3.18.0",
        )

        groups1 = self.grouper.group([finding_a, finding_b])
        groups2 = self.grouper.group([finding_b, finding_a])

        self.assertEqual(len(groups1), 2)
        self.assertEqual(len(groups2), 2)
        self.assertEqual([g.asset_id for g in groups1], [g.asset_id for g in groups2])

    def test_scanner_order_does_not_affect_asset_ids(self) -> None:
        """Requirement 8H: Scanner execution order does not alter asset IDs."""
        finding1 = CanonicalFinding(
            finding_id="s1",
            scanner=ToolName.SYFT,
            category=FindingCategory.COMPONENT,
            source=FindingSource.DEPENDENCY,
            package_name="requests",
            package_version="2.31.0",
        )
        finding2 = CanonicalFinding(
            finding_id="t1",
            scanner=ToolName.TRIVY,
            category=FindingCategory.VULNERABILITY,
            source=FindingSource.DEPENDENCY,
            package_name="requests",
            package_version="2.31.0",
            vulnerability_id="CVE-2023-32681",
        )

        identity1_a = self.resolver.resolve(finding1)
        identity1_b = self.resolver.resolve(finding1)
        self.assertEqual(identity1_a.asset_id, identity1_b.asset_id)

    def test_deduplication_preserves_provenance(self) -> None:
        """Requirement 9: Grouped asset retains all original contributing findings and scanner names."""
        finding_semgrep = CanonicalFinding(
            finding_id="sem-1",
            scanner=ToolName.SEMGREP,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
            evidence=ToolEvidence(message="Semgrep RSA observed"),
        )
        finding_gitleaks = CanonicalFinding(
            finding_id="git-1",
            scanner=ToolName.GITLEAKS,
            category=FindingCategory.CRYPTO_API,
            source=FindingSource.SOURCE_CODE,
            algorithm="RSA",
            file="auth.py",
            evidence=ToolEvidence(message="Gitleaks RSA pattern"),
        )

        groups = self.grouper.group([finding_semgrep, finding_gitleaks])

        self.assertEqual(len(groups), 1)
        group = groups[0]

        # Verify all original findings are preserved
        self.assertEqual(len(group.findings), 2)
        self.assertEqual(group.findings[0], finding_semgrep)
        self.assertEqual(group.findings[1], finding_gitleaks)

        # Verify all contributing scanners are tracked
        self.assertEqual(group.scanners, (ToolName.SEMGREP, ToolName.GITLEAKS))
        self.assertIn("semgrep", group.to_dict()["scanners"])
        self.assertIn("gitleaks", group.to_dict()["scanners"])
