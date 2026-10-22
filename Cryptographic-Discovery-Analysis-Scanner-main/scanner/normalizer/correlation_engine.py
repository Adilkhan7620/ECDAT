"""CorrelationEngine and CorrelationResult implementation for ECDAT."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Sequence
from uuid import NAMESPACE_URL, uuid5

from shared.models.finding import FindingCategory
from scanner.models.asset_identity import AssetGroup, AssetIdentity
from scanner.models.canonical_finding import CanonicalFinding
from scanner.models.unified_asset import (
    AssetRelationship,
    RelationshipType,
    UnifiedCryptoAsset,
)
from scanner.normalizer.asset_grouper import AssetGrouper, AssetIdentityResolver


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """Output container produced by CorrelationEngine."""

    unified_assets: tuple[UnifiedCryptoAsset, ...]
    relationships: tuple[AssetRelationship, ...]
    uncorrelated_findings: tuple[CanonicalFinding, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-serializable dictionary."""
        return {
            "unified_assets": [asset.to_dict() for asset in self.unified_assets],
            "relationships": [rel.to_dict() for rel in self.relationships],
            "uncorrelated_findings": [f.to_dict() for f in self.uncorrelated_findings],
        }

    def to_json(self) -> str:
        """Serialize as deterministic JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)


class CorrelationEngine:
    """Conservative, evidence-driven correlation engine for ECDAT discovery findings.

    Produces unified cryptographic assets and explicit relationships without false-positive merging.
    """

    def __init__(self, grouper: AssetGrouper | None = None) -> None:
        """Initialize correlation engine with optional AssetGrouper."""
        self._grouper = grouper or AssetGrouper()

    def correlate(self, findings: Sequence[CanonicalFinding]) -> CorrelationResult:
        """Correlate canonical findings into unified assets and explicit relationships."""
        # 1. Group findings by stable AssetIdentity
        asset_groups = self._grouper.group(findings)

        # 2. Build UnifiedCryptoAsset objects from asset groups
        unified_assets_map: dict[str, UnifiedCryptoAsset] = {}
        group_map: dict[str, AssetGroup] = {}

        for group in asset_groups:
            asset = UnifiedCryptoAsset.from_asset_group(group)
            unified_assets_map[asset.asset_id] = asset
            group_map[asset.asset_id] = group

        # 3. Derive explicit relationships based conservatively on evidence
        relationships = self._derive_relationships(unified_assets_map)

        # 4. Sort unified assets and relationships deterministically
        sorted_assets = tuple(
            unified_assets_map[asset_id]
            for asset_id in sorted(unified_assets_map.keys())
        )

        sorted_relationships = tuple(
            sorted(relationships, key=lambda r: r.relationship_id)
        )

        return CorrelationResult(
            unified_assets=sorted_assets,
            relationships=sorted_relationships,
            uncorrelated_findings=(),
        )

    def _derive_relationships(
        self, assets_map: dict[str, UnifiedCryptoAsset]
    ) -> list[AssetRelationship]:
        """Derive explicit relationships using strict evidence rules."""
        relationships: list[AssetRelationship] = []

        # Maps for fast lookup
        # package_name -> (package_version -> UnifiedCryptoAsset)
        package_assets: dict[str, dict[str, UnifiedCryptoAsset]] = {}
        vuln_assets: list[UnifiedCryptoAsset] = []
        cert_assets: list[UnifiedCryptoAsset] = []
        secret_assets: list[UnifiedCryptoAsset] = []
        crypto_api_assets: list[UnifiedCryptoAsset] = []

        for asset in assets_map.values():
            if asset.asset_type == FindingCategory.COMPONENT and asset.canonical_name.startswith("Component:"):
                pkg_name = asset.metadata.get("package_name") or (asset.canonical_name.split(":")[1].split("@")[0] if ":" in asset.canonical_name else None)
                pkg_ver = asset.metadata.get("package_version") or (asset.canonical_name.split("@")[1] if "@" in asset.canonical_name else None)
                if pkg_name and pkg_ver:
                    if pkg_name not in package_assets:
                        package_assets[pkg_name] = {}
                    package_assets[pkg_name][pkg_ver] = asset

            elif asset.asset_type == FindingCategory.VULNERABILITY:
                vuln_assets.append(asset)

            elif asset.asset_type == FindingCategory.CERTIFICATE:
                cert_assets.append(asset)

            elif asset.asset_type == FindingCategory.SECRET:
                secret_assets.append(asset)

            elif asset.asset_type == FindingCategory.CRYPTO_API:
                crypto_api_assets.append(asset)

        # RULE C / PACKAGE --AFFECTED_BY--> VULNERABILITY
        for v_asset in vuln_assets:
            # Check vulnerability evidence for package name and version
            for finding in v_asset.evidence:
                pkg_name = finding.package_name
                pkg_ver = finding.package_version
                if pkg_name and pkg_ver and pkg_name in package_assets and pkg_ver in package_assets[pkg_name]:
                    pkg_asset = package_assets[pkg_name][pkg_ver]
                    rel_id_key = f"rel:affected_by:{pkg_asset.asset_id}:{v_asset.asset_id}"
                    rel_id = str(uuid5(NAMESPACE_URL, rel_id_key))
                    supporting_ids = tuple(sorted({f.finding_id for f in v_asset.evidence + pkg_asset.evidence}))
                    relationships.append(
                        AssetRelationship(
                            relationship_id=rel_id,
                            source_asset_id=pkg_asset.asset_id,
                            relationship_type=RelationshipType.AFFECTED_BY,
                            target_asset_id=v_asset.asset_id,
                            confidence_basis="Matching package name and version between SBOM component and vulnerability finding",
                            supporting_finding_ids=supporting_ids,
                        )
                    )

        # SECRET --RELATED_TO--> CRYPTO_ASSET / SOURCE_CODE
        for secret_asset in secret_assets:
            for s_finding in secret_asset.evidence:
                if not s_finding.file:
                    continue
                # Match crypto API findings in the exact same file within 10 lines
                for api_asset in crypto_api_assets:
                    for a_finding in api_asset.evidence:
                        if a_finding.file == s_finding.file and s_finding.line_start is not None and a_finding.line_start is not None:
                            if abs(s_finding.line_start - a_finding.line_start) <= 10:
                                rel_id_key = f"rel:secret_api:{secret_asset.asset_id}:{api_asset.asset_id}"
                                rel_id = str(uuid5(NAMESPACE_URL, rel_id_key))
                                supporting_ids = tuple(sorted({s_finding.finding_id, a_finding.finding_id}))
                                relationships.append(
                                    AssetRelationship(
                                        relationship_id=rel_id,
                                        source_asset_id=secret_asset.asset_id,
                                        relationship_type=RelationshipType.RELATED_TO,
                                        target_asset_id=api_asset.asset_id,
                                        confidence_basis=f"Secret observation co-located in {s_finding.file} near line {s_finding.line_start}",
                                        supporting_finding_ids=supporting_ids,
                                    )
                                )

        # Deduplicate relationships by relationship_id
        unique_rels: dict[str, AssetRelationship] = {}
        for r in relationships:
            if r.relationship_id not in unique_rels:
                unique_rels[r.relationship_id] = r

        return list(unique_rels.values())
