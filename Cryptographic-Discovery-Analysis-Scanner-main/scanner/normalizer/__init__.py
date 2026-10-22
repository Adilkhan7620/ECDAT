"""Finding normalization boundary for future native-tool parsers."""

from scanner.models.canonical_finding import CanonicalFinding
from scanner.normalizer.asset_grouper import AssetGrouper, AssetIdentityResolver
from scanner.normalizer.confidence_classifier import ConfidenceClassifier
from scanner.normalizer.correlation_engine import CorrelationEngine, CorrelationResult
from scanner.normalizer.normalizer import FindingNormalizer

__all__ = [
    "AssetGrouper",
    "AssetIdentityResolver",
    "CanonicalFinding",
    "ConfidenceClassifier",
    "CorrelationEngine",
    "CorrelationResult",
    "FindingNormalizer",
]
