# Integration interfaces

WASP remains a self-contained executable. All integrations use a stable versioned report contract, not private Go internals or a duplicated TypeScript scanner.

## TypeScript SDK

`@<scope>/wasp` (placeholder until package name is reserved) invokes a trusted binary using `spawn(file, args, {shell:false})`, parses JSON from stdout, validates schema version, and returns typed results. APIs can include `scan(target, options)`, `version()` and `validateReport(report)`; process launch errors, timeouts, scope denials, findings gates and insufficient coverage are distinct. Prevent argument injection by constructing an argument array; never concatenate a shell command. Disallow arbitrary untrusted binary path by default and document trust boundary.

## GitHub Action

The Action delegates to a pinned, checksummed WASP release or bundled binary; it should not execute `curl | sh`. Accept `target`, `config`, `modules`, `fail-on`, `min-coverage` and `output` and expose `report-path`, `score`, `coverage`. Make upload to GitHub code scanning/artifacts optional and permission-gated. Use least-privilege `contents: read`; add `security-events: write` only where needed. Pin dependencies to commits where feasible.

## Other consumers

CLI JSON/SARIF reports can be ingested by any HTTP backend, job queue or database. Keep scan scheduling, auth, data retention and historical diffing outside the scanner; never add external backend API keys to the collector packages. Schema fixtures and compatibility tests are contract for consumers. Correlate scans by `scan_id` and target identity; report versions and policy fingerprints support reliable comparisons.
