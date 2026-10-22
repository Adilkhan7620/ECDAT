"""Command-line entry point for the ECDAT Scanner/Discovery Engine skeleton."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from scanner.orchestrator import ScanOrchestrator
from scanner.output import render_summary
from scanner.scanners import (
    GitleaksScanner,
    OpenSSLScanner,
    SemgrepScanner,
    SyftScanner,
    TrivyScanner,
)


def build_orchestrator() -> ScanOrchestrator:
    """Create the phase-one scanner registry."""
    return ScanOrchestrator(
        [SemgrepScanner(), GitleaksScanner(), SyftScanner(), TrivyScanner(), OpenSSLScanner()]
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(description="ECDAT Scanner/Discovery Engine skeleton")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run selected scanner skeleton adapters")
    scan.add_argument("target", type=Path, help="Existing local repository/application directory")
    scan.add_argument(
        "--scanner",
        action="append",
        choices=build_orchestrator().scanner_names,
        dest="scanners",
        help="Scanner to run; repeat for multiple scanners (default: all)",
    )

    analyze = subparsers.add_parser("analyze", help="Run end-to-end ECDAT analysis pipeline")
    analyze.add_argument("target", type=Path, help="Existing local repository/application directory")
    analyze.add_argument(
        "--scanner",
        action="append",
        choices=build_orchestrator().scanner_names,
        dest="scanners",
        help="Scanner to run; repeat for multiple scanners (default: all)",
    )

    subparsers.add_parser("doctor", help="Report configured scanner availability")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute the CLI and return a process exit code.

    Skeleton scan results intentionally return success because unavailable and
    not-implemented scanner states are expected, controlled outcomes.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        orchestrator = build_orchestrator()
        for name in orchestrator.scanner_names:
            scanner = orchestrator.get_scanner(name)
            state = "available" if scanner.is_available() else "unavailable"
            print(f"{name}: {state}")
        return 0

    if args.command == "analyze":
        import json
        from scanner.pipeline import EcdatAnalysisPipeline

        pipeline = EcdatAnalysisPipeline()
        try:
            analysis_result = pipeline.analyze(args.target, scanner_selection=args.scanners)
            print(json.dumps(analysis_result.to_dict(), indent=2))
        except Exception as error:
            parser.error(str(error))
            return 2
        return 0

    orchestrator = build_orchestrator()
    try:
        results = orchestrator.scan(args.target, args.scanners)
    except ValueError as error:
        parser.error(str(error))
        return 2

    print(render_summary(args.target, results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
