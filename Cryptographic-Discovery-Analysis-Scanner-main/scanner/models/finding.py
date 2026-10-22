"""Backward-compatible scanner import for the shared Finding contract."""

from shared.models.finding import Finding, FindingCategory, ToolEvidence

# Kept as a compatibility alias for skeleton code written before the shared
# contract was introduced. New consumers should use ``FindingCategory``.
FindingType = FindingCategory

__all__ = ["Finding", "FindingCategory", "FindingType", "ToolEvidence"]
