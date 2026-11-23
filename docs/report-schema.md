# Reports, diagnostics and compatibility

## Report envelope (v1)

```json
{
  "schema_version": "1.0.0",
  "scan_id": "e7d7b5e0-7cc6-4a57-a398-4ac5090662fa",
  "engine_version": "0.1.0",
  "policy_version": "default-v1",
  "target": {"input": "example.com", "canonical_url": "https://example.com", "hostname": "example.com"},
  "started_at": "2026-11-19T00:00:00Z",
  "completed_at": "2026-11-19T00:00:01Z",
  "status": "partial",
  "observations": [],
  "evaluations": [],
  "findings": [],
  "diagnostics": [],
  "coverage": {"fraction": 0.0, "planned": 0, "evaluable": 0},
  "score": {"value": null, "status": "insufficient_evidence"}
}
```

This is an **illustrative, zero-observation fixture**, not an example of a completed healthy audit. Validate full reports against `schemas/report.v1.schema.json`.

## Observations vs evaluations vs findings

`Observation`: source/probe ID, target/resource, timestamp, sanitized typed value, confidence and provenance. `Evaluation`: rule ID, resource, applicability, status and diagnostic refs. `Finding`: stable rule ID, severity, title, description, affected resource, sanitized evidence refs/summary, remediation and reference URLs. `Diagnostic`: module/probe, error code, message, retryability; never turn it into a low-severity finding. `Coverage`: attempted vs evaluable, plus missing/failed sections.

Stable IDs: `rule_id` is versioned catalog identity; `finding_id` should be stable hash of rule ID + normalized resource + relevant condition identity, avoiding timestamps and volatile raw values. Include separate observation IDs for linking.

## Evolution

- Semantic version `schema_version`; additive optional fields may be minor, breaking changes major.
- No secret values in default report; report producers sanitize evidence before serialization.
- Time values RFC3339 UTC; duration as integer milliseconds; IPs and URLs normalized and consistent.
- JSON output deterministic for equivalent evidence, except scan/timestamps which can be fixed in fixture mode.
- SARIF 2.1.0 is a mapping from findings, not a second rule engine; diagnostic errors and unknown checks must not be misrepresented as security findings.
- SDK must validate schema at runtime and reject unsupported major versions with actionable message.
