"""JSON rendering for CLI scan summaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from scanner.models.scan_result import ScannerResult


def render_summary(target: Path, results: Iterable[ScannerResult]) -> str:
    """Serialize scanner outcomes without writing files or exposing raw output."""
    payload = {
        "target": str(target),
        "results": [result.to_dict() for result in results],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
