"""Asset Identity Resolver and Asset Grouper implementation for ECDAT."""

from __future__ import annotations

from collections.abc import Iterable
from uuid import NAMESPACE_URL, uuid5

from shared.models.finding import FindingCategory
from scanner.models.asset_identity import AssetGroup, AssetIdentity
from scanner.models.canonical_finding import CanonicalFinding


class AssetIdentityResolver:
    """Resolves deterministic AssetIdentity instances from CanonicalFinding objects."""

    def resolve(self, finding: CanonicalFinding) -> AssetIdentity:
        """Resolve a deterministic asset identity based on available evidence category."""
        category = finding.category

        if category == FindingCategory.CRYPTO_API:
            return self._resolve_crypto_api(finding)

        if category == FindingCategory.SECRET:
            return self._resolve_secret(finding)

        if category == FindingCategory.COMPONENT:
            return self._resolve_component(finding)

        if category == FindingCategory.VULNERABILITY:
            return self._resolve_vulnerability(finding)

        if category == FindingCategory.CERTIFICATE:
            return self._resolve_certificate(finding)

        # Fallback for generic / unrecognized categories
        return self._resolve_generic(finding)

    def _resolve_crypto_api(self, finding: CanonicalFinding) -> AssetIdentity:
        """Strategy: file + algorithm + usage context."""
        loc = finding.file or "unknown_file"
        alg = finding.algorithm or "unknown_alg"
        usage_str = finding.usage.value if finding.usage else "unknown_usage"

        canonical_name = f"CryptoApi:{loc}:{alg}"
        # Deterministic UUID using location, algorithm, and usage
        identity_key = f"asset:crypto_api:{loc}:{alg}:{usage_str}"
        asset_id = str(uuid5(NAMESPACE_URL, identity_key))

        return AssetIdentity(
            asset_id=asset_id,
            asset_type=FindingCategory.CRYPTO_API,
            canonical_name=canonical_name,
            algorithm=finding.algorithm,
            key_size=finding.key_size,
            usage=finding.usage,
            location=finding.file,
            line_start=finding.line_start,
        )

    def _resolve_secret(self, finding: CanonicalFinding) -> AssetIdentity:
        """Strategy: file + secret rule type + line context. Never secret content."""
        loc = finding.file or "unknown_file"
        rule_type = finding.finding_type or "secret"
        line = finding.line_start or 0

        canonical_name = f"Secret:{rule_type}:{loc}"
        identity_key = f"asset:secret:{loc}:{rule_type}:{line}"
        asset_id = str(uuid5(NAMESPACE_URL, identity_key))

        return AssetIdentity(
            asset_id=asset_id,
            asset_type=FindingCategory.SECRET,
            canonical_name=canonical_name,
            location=finding.file,
            line_start=finding.line_start,
        )

    def _resolve_component(self, finding: CanonicalFinding) -> AssetIdentity:
        """Strategy: package_name + package_version + package_type."""
        pkg_name = finding.package_name or "unknown_package"
        pkg_ver = finding.package_version or "unknown_version"
        pkg_type = finding.package_type or "unknown_type"

        canonical_name = f"Component:{pkg_name}@{pkg_ver}"
        identity_key = f"asset:component:{pkg_name}:{pkg_ver}:{pkg_type}"
        asset_id = str(uuid5(NAMESPACE_URL, identity_key))

        return AssetIdentity(
            asset_id=asset_id,
            asset_type=FindingCategory.COMPONENT,
            canonical_name=canonical_name,
            package_name=finding.package_name,
            package_version=finding.package_version,
            package_type=finding.package_type,
            location=finding.file,
        )

    def _resolve_vulnerability(self, finding: CanonicalFinding) -> AssetIdentity:
        """Strategy: package identity + vulnerability ID."""
        pkg_name = finding.package_name or "unknown_package"
        pkg_ver = finding.package_version or "unknown_version"
        vuln_id = finding.vulnerability_id or finding.finding_type or "unknown_vuln"

        canonical_name = f"Vulnerability:{vuln_id}:{pkg_name}@{pkg_ver}"
        identity_key = f"asset:vulnerability:{vuln_id}:{pkg_name}:{pkg_ver}"
        asset_id = str(uuid5(NAMESPACE_URL, identity_key))

        return AssetIdentity(
            asset_id=asset_id,
            asset_type=FindingCategory.VULNERABILITY,
            canonical_name=canonical_name,
            vulnerability_id=finding.vulnerability_id,
            package_name=finding.package_name,
            package_version=finding.package_version,
            location=finding.file,
        )

    def _resolve_certificate(self, finding: CanonicalFinding) -> AssetIdentity:
        """Strategy: certificate serial / subject OR host/port endpoint."""
        endpoint = finding.metadata.get("endpoint")
        if isinstance(endpoint, str) and endpoint.strip():
            protocol = finding.protocol or "TLS"
            cipher = finding.cipher or "unknown_cipher"
            canonical_name = f"TLSEndpoint:{endpoint}"
            identity_key = f"asset:tls_endpoint:{endpoint}:{protocol}:{cipher}"
            asset_id = str(uuid5(NAMESPACE_URL, identity_key))
            return AssetIdentity(
                asset_id=asset_id,
                asset_type=FindingCategory.CERTIFICATE,
                canonical_name=canonical_name,
                subject=finding.subject,
                issuer=finding.issuer,
                protocol=finding.protocol,
                cipher=finding.cipher,
                algorithm=finding.algorithm,
                key_size=finding.key_size,
            )

        serial = finding.serial
        subject = finding.subject
        file_path = finding.file

        if serial or subject:
            ser_key = serial or "no_serial"
            subj_key = subject or "no_subject"
            canonical_name = f"Certificate:{subject or serial}"
            identity_key = f"asset:cert:{ser_key}:{subj_key}"
            asset_id = str(uuid5(NAMESPACE_URL, identity_key))
            return AssetIdentity(
                asset_id=asset_id,
                asset_type=FindingCategory.CERTIFICATE,
                canonical_name=canonical_name,
                subject=finding.subject,
                issuer=finding.issuer,
                serial=finding.serial,
                algorithm=finding.algorithm,
                key_size=finding.key_size,
                location=finding.file,
            )

        loc_key = file_path or "unknown_cert_file"
        canonical_name = f"CertificateFile:{loc_key}"
        identity_key = f"asset:cert_file:{loc_key}"
        asset_id = str(uuid5(NAMESPACE_URL, identity_key))
        return AssetIdentity(
            asset_id=asset_id,
            asset_type=FindingCategory.CERTIFICATE,
            canonical_name=canonical_name,
            algorithm=finding.algorithm,
            key_size=finding.key_size,
            location=finding.file,
        )

    def _resolve_generic(self, finding: CanonicalFinding) -> AssetIdentity:
        """Fallback identity resolution strategy."""
        loc = finding.file or "unknown_loc"
        ftype = finding.finding_type or "generic"
        canonical_name = f"Asset:{ftype}:{loc}"
        identity_key = f"asset:generic:{ftype}:{loc}:{finding.finding_id}"
        asset_id = str(uuid5(NAMESPACE_URL, identity_key))
        return AssetIdentity(
            asset_id=asset_id,
            asset_type=finding.category,
            canonical_name=canonical_name,
            location=finding.file,
            line_start=finding.line_start,
        )


class AssetGrouper:
    """Groups CanonicalFinding objects by their stable AssetIdentity."""

    def __init__(self, resolver: AssetIdentityResolver | None = None) -> None:
        """Initialize AssetGrouper with an optional resolver instance."""
        self._resolver = resolver or AssetIdentityResolver()

    def group(self, findings: Iterable[CanonicalFinding]) -> tuple[AssetGroup, ...]:
        """Group canonical findings by asset_id into AssetGroup objects.

        Deduplication behavior:
        - Groups findings sharing the same deterministic asset_id.
        - Preserves all original findings without deleting evidence.
        - Finding order and scanner order do not alter the resulting asset IDs.
        - Returns AssetGroup tuple sorted deterministically by asset_id.
        """
        # Map asset_id -> (AssetIdentity, list[CanonicalFinding])
        groups_map: dict[str, tuple[AssetIdentity, list[CanonicalFinding]]] = {}

        for finding in findings:
            identity = self._resolver.resolve(finding)
            asset_id = identity.asset_id

            if asset_id not in groups_map:
                groups_map[asset_id] = (identity, [finding])
            else:
                groups_map[asset_id][1].append(finding)

        # Sort asset groups deterministically by asset_id
        sorted_asset_ids = sorted(groups_map.keys())

        asset_groups: list[AssetGroup] = []
        for asset_id in sorted_asset_ids:
            identity, group_findings = groups_map[asset_id]
            asset_groups.append(
                AssetGroup(
                    identity=identity,
                    findings=tuple(group_findings),
                )
            )

        return tuple(asset_groups)
