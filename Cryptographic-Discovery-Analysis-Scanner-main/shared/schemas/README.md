# ECDAT shared schemas

`ecdat-finding.schema.json` is the version-controlled, scanner-independent
exchange contract for a raw or normalized ECDAT Finding.

Consumers such as the future Correlation Engine should read findings as JSON
validated against this schema. They must not import scanner adapters or rely on
tool-specific metadata keys. A native rule identifier may be supplied through
`rule`; other tool-specific evidence remains under `evidence.original` and
`metadata`.

The contract deliberately excludes final CBOM, quantum-risk, blast-radius,
PQC recommendation, and compliance fields. Those are produced by later ECDAT
modules after correlation.
