# ECDAT Scanner / Discovery Engine

This is the Python skeleton for ECDAT's first development phase. It owns only
local-path scan orchestration and scanner-specific adapter boundaries.

It does not execute Semgrep, Gitleaks, Syft, Trivy, or OpenSSL yet. Therefore
it runs without those tools installed and reports controlled `tool_unavailable`
or `not_implemented` outcomes instead.

## Run

From the repository root:

```bash
python -m scanner.main doctor
python -m scanner.main scan .
python -m scanner.main scan . --scanner semgrep --scanner openssl
```

The scan command accepts existing local directories only and prints a JSON
summary. It does not generate a CBOM, correlate findings, assess risk, or call
any frontend/backend service.

## Test

```bash
python -m unittest discover -s scanner/tests -v
```

## Package layout

- `core/`: `BaseScanner` contract.
- `models/`: common evidence-level `Finding` and scanner outcomes.
- `scanners/`: one adapter boundary per documented security tool.
- `orchestrator/`: independent scanner dispatch only.
- `normalizer/`: common-Finding boundary; no correlation.
- `output/`: JSON summary rendering.
