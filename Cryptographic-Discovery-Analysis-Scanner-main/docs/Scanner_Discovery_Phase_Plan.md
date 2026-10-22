# ECDAT Scanner / Discovery Engine — Phase 1 Implementation Plan

## 1. Scope and boundaries

This phase builds only the independently runnable **Scanner / Discovery Engine** for a local repository or application directory. It invokes the documented tools — **Semgrep, Gitleaks, Syft, Trivy, and OpenSSL** — preserves each tool's raw output, parses each output independently, and emits a common, *unreconciled* ECDAT Finding collection.

This phase deliberately does **not** implement:

- correlation, deduplication, confidence scoring, or conflict resolution;
- final CBOM creation or signing;
- quantum-risk scoring, Mosca calculations, blast-radius calculations, PQC recommendations, reachability, or compliance verdicts;
- a frontend, Spring Boot API, database persistence, container/runtime/network discovery, YARA scanning, or proprietary/custom-cryptography detection.

The implementation is static local-path discovery. The target is never uploaded or sent to an external service by this module.

> Documentation note: `docs/ECDAT_Final_Report.md` was not present in this checkout. This plan was based on `docs/sih_research.pdf` and the available `docs/ECDAT_Master_Hackathon_Guide.html`, which supplies the same ECDAT architecture and scan-tool scope.

## 2. Proposed folder structure

```text
ECDAT/
├── docs/
│   └── Scanner_Discovery_Phase_Plan.md
├── scanner-engine/                         # independently runnable phase-one package
│   ├── README.md                            # prerequisites and CLI use
│   ├── pyproject.toml                       # runtime/test/tool configuration
│   ├── src/ecdat_scanner/
│   │   ├── cli.py                            # `ecdat-scan` command entry point
│   │   ├── orchestrator.py                   # validates target and coordinates runners
│   │   ├── models/
│   │   │   ├── finding.py                    # common Finding schema / enums
│   │   │   ├── scan.py                       # request, status, result and manifest models
│   │   │   └── errors.py                     # typed domain errors
│   │   ├── scanners/
│   │   │   ├── base.py                       # scanner contract
│   │   │   ├── semgrep.py                    # command construction + parser binding
│   │   │   ├── gitleaks.py
│   │   │   ├── syft.py
│   │   │   ├── trivy.py
│   │   │   └── openssl.py                    # certificate/public-key inspection wrapper
│   │   ├── parsers/
│   │   │   ├── base.py
│   │   │   ├── semgrep.py
│   │   │   ├── gitleaks.py
│   │   │   ├── syft.py
│   │   │   ├── trivy.py
│   │   │   └── openssl.py
│   │   ├── normalization/
│   │   │   ├── locations.py                  # path and line normalization
│   │   │   ├── algorithms.py                 # canonical algorithm/family labels only
│   │   │   └── findings.py                   # parser records -> ECDAT Finding
│   │   ├── execution/
│   │   │   ├── process.py                    # safe subprocess execution, timeout, capture
│   │   │   └── discovery.py                  # eligible certificate/key-file enumeration
│   │   ├── storage/
│   │   │   ├── artifacts.py                  # per-run raw output and manifest layout
│   │   │   └── result_writer.py              # normalized JSON/JSONL output
│   │   └── logging.py                         # structured logging configuration
│   └── tests/
│       ├── fixtures/                         # versioned, sanitized native-tool output
│       ├── unit/                             # parser, normalization, command tests
│       ├── integration/                      # tool runs against small local fixtures
│       └── contract/                         # Finding schema and correlation hand-off tests
└── contracts/
    └── finding.schema.json                   # versioned inter-module exchange contract
```

`scanner-engine` stays independently buildable and executable. `contracts/finding.schema.json` is deliberately outside the package so the future Correlation Engine can validate the same artifact without importing scanner implementation code.

## 3. Module responsibilities

| Module | Responsibility | Explicitly not responsible for |
|---|---|---|
| CLI | Parse arguments, select tools, configure output and report exit status | Serving an API or presenting UI |
| Orchestrator | Validate a local target; create a scan ID; run enabled scanners; collect outcomes | Deduplication or risk decisions |
| Scanner adapters | Verify executable availability, build a safe native command, execute it, retain native output | Interpreting another tool's format |
| Per-tool parsers | Convert exactly one tool's documented JSON/SBOM output into parser records | Cross-tool merging |
| Normalization | Map parser records to the versioned ECDAT Finding contract and canonical source locations | Assigning a reconciled confidence or final asset ID |
| Artifact storage | Store raw stdout/stderr/native report plus scan manifest and normalized output | Database persistence / CBOM export |
| Contract package | Define validation rules and compatibility version | Future business analysis |

Tool-specific discovery intent remains within documented scope:

- **Semgrep:** crypto-related source API/configuration matches using the ECDAT rule pack.
- **Gitleaks:** secret findings that can indicate exposed cryptographic material; it does not claim to determine final asset risk.
- **Syft:** package/SBOM component evidence, including libraries that provide cryptographic functionality where reported.
- **Trivy:** local filesystem/image-relevant dependency and vulnerability evidence as emitted by the selected documented scan mode.
- **OpenSSL:** inspect discovered certificate and public-key artifacts for subject, issuer, validity, public-key algorithm, and key size. Private-key content is never parsed into the normalized result.

## 4. Data flow

```text
Local path
    |
    v
CLI request validation -> scan ID + immutable run directory
    |
    +--> Semgrep adapter  -> raw/semgrep.*  -> Semgrep parser  --+
    +--> Gitleaks adapter -> raw/gitleaks.* -> Gitleaks parser --+
    +--> Syft adapter     -> raw/syft.*     -> Syft parser     --+--> normalization
    +--> Trivy adapter    -> raw/trivy.*    -> Trivy parser    --+        |
    +--> OpenSSL adapter  -> raw/openssl/*  -> OpenSSL parser  --+        v
                                                                  findings.jsonl
                                                                  scan-manifest.json
                                                                  summary.json
                                                                        |
                                                                        v
                                                         Future Correlation Engine input
```

Scanners can execute concurrently because their inputs are read-only and their artifacts are isolated by scanner name. Normalized output is appended deterministically (scanner order, then native result order) so the same fixture produces a stable result. The engine emits all findings separately: shared locations, libraries, or algorithms are evidence for the future Correlation Engine, not grounds for merging here.

Each scan run has this on-disk layout:

```text
<output-dir>/<scan-id>/
├── scan-manifest.json
├── raw/
│   ├── semgrep.json        ├── gitleaks.json
│   ├── syft.spdx.json      ├── trivy.json
│   └── openssl/            # one native report per inspected artifact
├── normalized/
│   ├── findings.jsonl
│   └── findings.schema-version.json
├── logs/scan.jsonl
└── summary.json
```

## 5. Common ECDAT Finding schema

The schema is an *evidence-level* record, not a final `crypto_asset`/CBOM record. It preserves one source tool and one native finding reference per record, allowing later reconciliation to calculate `detected_by` and confidence honestly.

```json
{
  "schema_version": "1.0",
  "finding_id": "uuid",
  "scan_id": "uuid",
  "scanner": "semgrep",
  "scanner_finding_id": "native-result-id-or-deterministic-reference",
  "finding_type": "crypto_api | secret | component | vulnerability | certificate | public_key",
  "subject": {
    "kind": "source_file | dependency | certificate | public_key | secret",
    "name": "optional display name",
    "purl": "optional package URL",
    "version": "optional component version"
  },
  "crypto": {
    "algorithm": "optional canonical algorithm name",
    "algorithm_family": "optional asymmetric | symmetric | hash | mac | kdf | unknown",
    "key_size_bits": 2048,
    "usage_hint": "optional encryption | key_exchange | signature | hash | unknown"
  },
  "location": {
    "path": "relative/to/scan-root",
    "line_start": 12,
    "line_end": 12,
    "column_start": 4,
    "column_end": 20
  },
  "evidence": {
    "message": "tool-produced description",
    "rule_id": "optional native rule/advisory identifier",
    "native_severity": "optional native severity string",
    "raw_artifact": "raw/semgrep.json",
    "raw_pointer": "JSON Pointer or OpenSSL artifact-relative reference"
  },
  "tool": {
    "name": "semgrep",
    "version": "detected tool version",
    "command": ["semgrep", "..."],
    "completed_at": "RFC 3339 UTC timestamp"
  },
  "status": "observed"
}
```

Rules:

- Required scalar fields use `null` only where marked optional; missing/unknown cryptographic attributes remain absent/null rather than inferred.
- `location.path` is always relative to the supplied target and must not escape it.
- `raw_artifact` and `raw_pointer` are mandatory provenance links for successful parsed findings.
- Native severity and messages are evidence, not ECDAT risk classifications.
- There are no `quantum_risk`, `reachability`, `policy_status`, `india_compliance`, `pqc_recommendation`, `confidence`, or final `detected_by` fields in this phase. The later layers own them.

## 6. Scanner interface

Each adapter implements the same contract. The concrete language can be finalized at implementation; the interface is intentionally language-neutral.

```text
ScannerAdapter
  name() -> ScannerName
  preflight() -> ToolAvailability
  build_request(target: LocalPath, run: ScanContext) -> NativeCommand
  execute(command: NativeCommand, timeout: Duration) -> RawExecution
  parse(raw: RawExecution, context: ScanContext) -> list[ParsedRecord]
  normalize(records: list[ParsedRecord], context: ScanContext) -> list[EcdatFinding]
```

`RawExecution` includes argv, exit code, start/end times, stdout path, stderr path, native report path, and parser status. The command is passed as an argument array with no shell interpolation. Each adapter also exposes a single-tool CLI path through the common CLI (`--scanner semgrep`, etc.), satisfying independent executability without duplicating code.

OpenSSL differs only in cardinality: its adapter first enumerates eligible certificate/public-key files under the target, then creates one command/result per artifact and aggregates them into its scanner result. It uses a bounded file-size policy and safe file-type detection; it does not invoke OpenSSL against arbitrary binary files or ingest key material into logs.

## 7. Error-handling strategy

The engine is best-effort by scanner and fail-fast only for invalid scan requests.

| Situation | Behavior | Exit/result effect |
|---|---|---|
| Target missing, unreadable, or not a directory | Reject before running tools | request failure; no partial run |
| Tool executable missing | Mark that scanner `UNAVAILABLE`, write manifest entry, continue other selected tools | non-zero partial-success exit if no other scanner succeeds |
| Tool timeout / non-zero execution failure | Preserve stdout/stderr, mark scanner `FAILED`, continue | partial-success exit when another scanner succeeds |
| Native output is malformed or unsupported | Preserve raw output, mark parser `FAILED`; do not fabricate findings | partial-success exit when another scanner succeeds |
| One OpenSSL artifact is unreadable/unsupported | Record an artifact-level warning and continue remaining eligible artifacts | scanner can still succeed |
| Output cannot be written | Stop safely and return an infrastructure error | failure |
| Individual record lacks fields | Emit only the supported fields, preserving provenance | no inferred values |

Use distinct process exits: `0` all requested scanners succeeded; `2` partial success; `3` invalid request/preflight failure; `4` no selected scanner produced usable normalized output; `5` internal/output-storage failure. `summary.json` and `scan-manifest.json` are the authoritative machine-readable status, independent of exit code.

Raw output can contain secrets (especially Gitleaks). It is a required audit artifact, so it must be stored with owner-only permissions by default, excluded from source control, never emitted to console logs, and clearly identified in the manifest as sensitive. Console summaries expose counts and artifact paths only.

## 8. Logging strategy

Emit structured JSONL logs to `<run>/logs/scan.jsonl` and a concise human-readable progress stream to stderr. Every event includes UTC timestamp, scan ID, scanner name (when applicable), event name, duration, and outcome.

Important events: `scan_started`, `target_validated`, `scanner_preflight`, `scanner_started`, `raw_artifact_written`, `parser_completed`, `normalization_completed`, `scanner_failed`, `scan_completed`.

Log only metadata: target path, selected scanners, command executable/arguments after secret-safe filtering, artifact paths, counts, exit status, and exception classification. Never log source snippets, secret values, private-key content, full native findings, or raw stdout/stderr. `--log-level` governs detail; `--debug` may include stack traces but keeps the same content-redaction rules.

## 9. CLI design

Primary command:

```bash
ecdat-scan scan /absolute/or/relative/local/path \
  --output ./ecdat-runs \
  --scanner semgrep --scanner gitleaks --scanner syft --scanner trivy --scanner openssl \
  --timeout 300 \
  --format jsonl
```

Defaults:

- all five scanners selected;
- local directory targets only;
- a generated scan ID and `./ecdat-runs` output directory;
- JSONL normalized findings plus JSON manifest and summary;
- bounded per-scanner timeout.

Subcommands:

```text
ecdat-scan scan <target> [options]       Run selected scanners and write artifacts/results.
ecdat-scan doctor [--scanner <name>]     Report installed tool availability and supported formats.
ecdat-scan schema                        Print the Finding contract version/location.
```

Useful options are limited to phase-one scope: `--scanner`, `--output`, `--scan-id`, `--timeout`, `--max-workers`, `--format`, `--keep-raw` (default true; disabling it is explicitly warned because it forfeits provenance), `--log-level`, and `--fail-fast` (off by default). There is no option for risk, CBOM, correlation, frontend, remote repository cloning, or policy evaluation.

## 10. Testing strategy

1. **Schema contract tests** validate every normalized record against `contracts/finding.schema.json`, require provenance links, reject absolute/traversing locations, and verify no later-phase fields appear.
2. **Parser unit tests** use captured, sanitized native outputs for each tool: valid output, empty output, malformed output, missing optional fields, changed tool-version fields, and multiple finding types.
3. **Normalization unit tests** cover canonical paths, line ranges, algorithm names when directly supported by native evidence, and preservation of unknown values.
4. **Scanner command tests** assert argv construction, no shell use, target confinement, timeout propagation, and OpenSSL eligible-artifact filtering.
5. **Orchestration tests** use fake adapters to cover parallel completion, partial failures, all-failed behavior, manifest correctness, ordering, raw artifact persistence, and exit-code mapping.
6. **Integration tests** run installed tools only against small, non-secret local fixture repositories and certificate files. They are capability-gated so a missing locally installed tool skips rather than falsely passes its integration suite.
7. **Compatibility tests** pin supported native-tool output fixtures and detect parser regressions before a tool-version upgrade is accepted.

No tests calculate quantum risk, generate a CBOM, deduplicate findings, or assess compliance in this phase.

## 11. Future Correlation Engine integration points

The Scanner / Discovery Engine hands off a scan bundle, not a final asset inventory:

```text
ScanBundle = {
  scan_id,
  target_metadata,
  scanner_statuses,
  findings_uri,
  finding_schema_version,
  raw_artifact_index_uri,
  completed_at
}
```

The future Correlation Engine will consume `findings.jsonl` plus the manifest, then own:

- grouping related evidence by normalized path, component PURL/version, certificate fingerprint, algorithm, and later-defined relationships;
- deduplication and conflict resolution;
- calculation of `detected_by` and a documented ensemble confidence score;
- creation of a correlated asset ID / crypto-asset record fit for downstream CBOM generation.

To make that safe, phase one guarantees stable scan and finding identifiers, a schema version, per-finding raw evidence pointers, scanner/tool version metadata, relative target locations, and non-destructive preservation of tool outputs. Correlation must treat scanner statuses as evidence availability, not silently assume that an absent tool implies an absent asset.

## 12. Implementation acceptance criteria

- `ecdat-scan scan <local-directory>` executes without Spring Boot or the frontend.
- Any one named scanner can be run alone using `--scanner`.
- Every selected scanner has a distinct adapter and parser.
- A scan run retains native raw output, stderr, command/tool metadata, scanner status, normalized findings, and a summary.
- Every normalized finding validates against the shared Finding contract and links back to raw evidence.
- A single scanner failure does not discard successful output from other scanners.
- Output contains no final CBOM, quantum-risk, PQC, blast-radius, correlation, or compliance result.
- The resulting bundle can be consumed by a separately built Correlation Engine with no scanner-package import.
